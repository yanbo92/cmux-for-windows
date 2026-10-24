//! Exercise the shipped executable through Noise and the mux control service.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cmux_remote::connection::{ClientConnection, ClientConnectionConfig, ReconnectPolicy};
use cmux_remote::crypto::{ClientAuthMode, StaticIdentity};
use cmux_remote::link::FrameLink;
use cmux_remote::provider::{
    CarrierEvidence, LengthDelimitedLink, LinkGroup, LinkRequest, ProviderCapabilities,
    ProviderError,
};
use cmux_remote::service::{EndpointRole, ServiceMultiplexer};
use cmux_remote::session::SessionLimits;
use cmux_remote_protocol::{Lane, LanePolicy, Service, SessionId};
use tokio::process::Command;
use tokio::sync::Mutex;

struct StdioGroup(Mutex<Option<Box<dyn FrameLink>>>);

#[async_trait]
impl LinkGroup for StdioGroup {
    fn description(&self) -> &str {
        "remote-link-test"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::STREAM
    }

    fn evidence(&self) -> &CarrierEvidence {
        &CarrierEvidence::None
    }

    async fn open(&self, _: LinkRequest) -> Result<Box<dyn FrameLink>, ProviderError> {
        self.0.lock().await.take().ok_or_else(|| ProviderError::Transport("already opened".into()))
    }

    async fn close(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[tokio::test]
async fn ssh_stdio_serves_real_mux_identify_after_noise_handshake() {
    let state = tempfile::tempdir().unwrap();
    let session = format!("remote-link-test-{}", std::process::id());
    let socket = cmux_tui_core::server::default_socket_path(&session);
    let mut owner = Command::new(env!("CARGO_BIN_EXE_cmux-tui"))
        .args(["--headless", "--ephemeral", "--session", &session, "--socket"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if cmux_tui_core::platform::transport::connect(&socket).is_ok() {
                break;
            }
            assert!(owner.try_wait().unwrap().is_none(), "mux owner exited during startup");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("mux did not start");

    let mut server = Command::new(env!("CARGO_BIN_EXE_cmux-tui"))
        .args(["remote-link", "--stdio", "--session", &session, "--state-dir"])
        .arg(state.path())
        .arg("--mux-socket")
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let link = LengthDelimitedLink::new(
        "remote-link-test",
        65_535,
        server.stdout.take().unwrap(),
        server.stdin.take().unwrap(),
    );
    let group = Arc::new(StdioGroup(Mutex::new(Some(Box::new(link)))));
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let client = ClientConnection::connect(
            group,
            ClientConnectionConfig {
                identity: StaticIdentity::generate().unwrap(),
                expected_daemon: None,
                auth: ClientAuthMode::Carrier,
                device_name: "remote-link-test".into(),
                session: SessionId([1; 16]),
                lane_policy: LanePolicy::Single,
                limits: SessionLimits::default(),
                reconnect: ReconnectPolicy {
                    heartbeat_interval: None,
                    maximum_attempts: Some(1),
                    ..ReconnectPolicy::default()
                },
            },
        )
        .await
        .unwrap();
        let mux = ServiceMultiplexer::new(client.clone(), EndpointRole::Client);
        let stream = mux.open(Service::MuxControl, BTreeMap::new()).await.unwrap();
        for _ in 0..3 {
            let opened = stream.receive().await.unwrap().unwrap();
            let opened: serde_json::Value = serde_json::from_slice(&opened.payload).unwrap();
            assert_eq!(opened["type"], "opened", "mux service was rejected");
        }
        // One CMXL packet containing a real JSONL request. A handshake-only
        // stub or an unavailable Windows mux bridge cannot satisfy this.
        let mut packet = b"CMXL".to_vec();
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(&0_u32.to_be_bytes());
        packet.extend_from_slice(&1_u32.to_be_bytes());
        packet.extend_from_slice(b"{\"id\":1,\"cmd\":\"identify\"}\n");
        stream.send_on(Lane::Control, Bytes::from(packet)).await.unwrap();
        let response = stream.receive().await.unwrap().unwrap();
        assert_eq!(&response.payload[..4], b"CMXL");
        let response: serde_json::Value = serde_json::from_slice(&response.payload[20..]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["ok"], true, "{response}");
        client.close().await.unwrap();
    })
    .await;
    let _ = server.kill().await;
    let _ = server.wait().await;
    let _ = owner.kill().await;
    let _ = owner.wait().await;
    let _ = std::fs::remove_file(socket);
    result.expect("remote-link handshake or mux request timed out");
}
