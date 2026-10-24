//! Foreground SSH remote-link server.
//!
//! The Mac client starts this command over SSH and carries the authenticated
//! cmux protocol over stdin/stdout. Keeping the daemon in this process avoids
//! Unix socket assumptions on Windows while preserving the upstream framing,
//! Noise handshake, and workspace service stack.

use std::path::PathBuf;

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
    if !session.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)) {
        return Err(anyhow!("remote session name is not shell-safe"));
    }
    let state_dir = option_value(args, "--state-dir")
        .map(PathBuf::from)
        .or_else(default_state_dir)
        .ok_or_else(|| anyhow!("could not determine a Windows remote state directory"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not start remote Tokio runtime")?;
    runtime.block_on(serve(session, state_dir))
}

async fn serve(session: String, state_dir: PathBuf) -> anyhow::Result<()> {
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
    let services = DaemonServices::new(workspace, None);

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
    let result = services.serve_client(client).await.map_err(|error| anyhow!(error));
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
