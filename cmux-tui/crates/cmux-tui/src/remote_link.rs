//! Foreground SSH remote-link server.
//!
//! The Mac client starts this command over SSH and carries the authenticated
//! cmux protocol over stdin/stdout. Keeping the daemon in this process avoids
//! Unix socket assumptions on Windows while preserving the upstream framing,
//! Noise handshake, and workspace service stack.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use cmux_remote::crypto::InboundAuthEvidence;
use cmux_remote::daemon::{DaemonSessionPolicy, InboundLink, RemoteDaemon};
use cmux_remote::identity::AuthDatabase;
use cmux_remote::provider::LengthDelimitedLink;
use cmux_remote::services::DaemonServices;
use cmux_remote::session::SessionLimits;
use cmux_remote::workspace::WorkspaceService;

const MAX_CARRIER_FRAME_BYTES: usize = 65_535;

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("cmux-tui: remote-link failed: {error:#}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> anyhow::Result<()> {
    if !args.iter().any(|argument| argument == "--stdio") {
        return Err(anyhow!("remote-link currently requires --stdio"));
    }
    let session = option_value(args, "--session").unwrap_or_else(|| "main".into());
    if session.is_empty()
        || session.len() > 120
        || !session.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        || session == "."
        || session == ".."
    {
        return Err(anyhow!("remote session name is not shell-safe"));
    }
    let state_dir = option_value(args, "--state-dir")
        .map(PathBuf::from)
        .or_else(default_state_dir)
        .ok_or_else(|| anyhow!("could not determine a Windows remote state directory"))?
        .join("sessions")
        .join(&session);
    let mux_socket = option_value(args, "--mux-socket")
        .map(PathBuf::from)
        .unwrap_or_else(|| cmux_tui_core::server::default_socket_path(&session));
    ensure_mux_owner(&session, &state_dir, &mux_socket)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not start remote Tokio runtime")?;
    runtime.block_on(serve(session, state_dir, mux_socket))
}

fn ensure_mux_owner(session: &str, state_dir: &Path, socket: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state_dir.join("start.lock"))?;
    fs4::FileExt::lock(&lock)?;
    if cmux_tui_core::platform::transport::connect(socket).is_ok() {
        return Ok(());
    }
    let log_path = state_dir.join("mux.log");
    let log = OpenOptions::new().create(true).append(true).open(&log_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--headless", "--session", session, "--socket"])
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    let mut child = {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
            // Win32-OpenSSH confines each session to a kill-on-close job
            // object, so a detached owner still dies with its SSH carrier.
            // Break the owner out so it survives carrier loss and reconnects
            // reuse live terminals. Jobs that forbid breakaway reject the
            // escape flag, so fall back to a plain detached spawn.
            let escaped = command
                .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
                .spawn();
            match escaped {
                Ok(child) => Ok(child),
                Err(_) => {
                    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
                    command.spawn()
                }
            }
        }
        #[cfg(not(windows))]
        {
            command.spawn()
        }
    }
    .context("could not start remote mux owner")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if cmux_tui_core::platform::transport::connect(socket).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!("remote mux exited {status}; inspect {}", log_path.display()));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("remote mux startup timed out; inspect {}", log_path.display()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn serve(session: String, state_dir: PathBuf, mux_socket: PathBuf) -> anyhow::Result<()> {
    let auth = AuthDatabase::load_or_create(&state_dir, format!("cmux-vdi-{session}"), true)
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!("could not open remote state directory {}", state_dir.display())
        })?;
    let (daemon, mut clients) = RemoteDaemon::with_policy(
        auth.clone(),
        SessionLimits::default(),
        DaemonSessionPolicy::default(),
    )
    .map_err(|error| anyhow!(error))?;
    let workspace = WorkspaceService::new();
    let services = DaemonServices::new(workspace, Some(mux_socket));

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let link = LengthDelimitedLink::new("ssh-stdio", MAX_CARRIER_FRAME_BYTES, stdin, stdout);
    let evidence = InboundAuthEvidence::ssh("ssh-session")
        .ok_or_else(|| anyhow!("SSH authentication evidence is empty"))?;
    daemon
        .accept(InboundLink::new(Box::new(link), evidence))
        .await
        .map_err(|error| anyhow!(error))
        .context("remote Noise handshake or authorization failed")?;

    let client = clients
        .recv()
        .await
        .ok_or_else(|| anyhow!("remote daemon closed before accepting the SSH client"))?;
    let local = tokio::task::LocalSet::new();
    let result =
        local.run_until(services.serve_client(client)).await.map_err(|error| anyhow!(error));
    let auth_result = auth.shutdown().await.map_err(|error| anyhow!(error));
    result.and(auth_result)
}

fn option_value(args: &[String], option: &str) -> Option<String> {
    args.windows(2).find(|pair| pair[0] == option).map(|pair| pair[1].clone())
}

fn default_state_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CMUX_REMOTE_STATE_DIR") {
        return Some(path.into());
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("cmux").join("remote"))
    }
    #[cfg(not(windows))]
    {
        cmux_remote::identity::default_state_dir()
    }
}
