//! Authenticated, bounded named-pipe RPC server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA, ERROR_NO_SYSTEM_RESOURCES,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED, ERROR_TOO_MANY_OPEN_FILES,
};

use super::dispatch;
use super::protocol::{Request, Response, PIPE_NAME};
use super::security::{self, Installation, PipeSecurity};

// Keep the complete privileged wire request bounded independently of any
// semantic payload limit. The client checks the encoded envelope too.
const MAX_REQUEST_BYTES: usize = 1536 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INSTANCES: usize = 4;
const MAX_CLIENT_WORKERS: usize = MAX_INSTANCES - 1;
pub const RPC_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

fn create_pipe(first_instance: bool, owner_sid: &str) -> Result<NamedPipeServer> {
    let mut security = PipeSecurity::for_owner(owner_sid)?;
    let attrs = security.as_attrs_ptr();
    let mut opts = ServerOptions::new();
    opts.max_instances(MAX_INSTANCES)
        .reject_remote_clients(true);
    if first_instance {
        opts.first_pipe_instance(true);
    }
    let server = unsafe {
        opts.create_with_security_attributes_raw(PIPE_NAME, attrs)
            .with_context(|| format!("CreateNamedPipe {PIPE_NAME}"))?
    };
    Ok(server)
}

pub struct PreparedPipeServer {
    installation: Arc<Installation>,
    server: NamedPipeServer,
}

/// Complete all fail-closed startup checks and create the first pipe instance
/// before the SCM service is allowed to report `Running`.
pub fn prepare_pipe_server() -> Result<PreparedPipeServer> {
    let installation = Arc::new(Installation::load().context("helper trust manifest rejected")?);
    installation
        .verify_runtime_marker()
        .context("protected runtime provisioning is incomplete")?;
    let server = create_pipe(true, &installation.owner_sid)?;
    Ok(PreparedPipeServer {
        installation,
        server,
    })
}

/// The server refuses to start unless protected installer metadata and every
/// referenced binary validate successfully.
pub async fn run_pipe_server(shutdown: Arc<AtomicBool>) -> Result<()> {
    let prepared = prepare_pipe_server()?;
    run_prepared_pipe_server(prepared, shutdown).await
}

pub async fn run_prepared_pipe_server(
    prepared: PreparedPipeServer,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let PreparedPipeServer {
        installation,
        mut server,
    } = prepared;
    eprintln!(
        "[helper-pipe] listening {PIPE_NAME}, install_id={}",
        installation.install_id
    );

    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let workers = Arc::new(Semaphore::new(MAX_CLIENT_WORKERS));
    let mut tasks = JoinSet::new();

    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                eprintln!("[helper-pipe] client worker join failed: {error}");
            }
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let permit = tokio::select! {
            permit = workers.clone().acquire_owned() => permit.context("pipe worker semaphore closed")?,
            _ = tick.tick() => continue,
        };
        tokio::select! {
            connect_result = server.connect() => {
                if let Err(error) = connect_result {
                    if !is_transient_accept_error(&error) {
                        return Err(error).context("named-pipe accept failed");
                    }
                    drop(server);
                    let Some(replacement) = create_replacement_pipe(&installation.owner_sid, &shutdown).await? else {
                        break;
                    };
                    server = replacement;
                    drop(permit);
                    continue;
                }
                let connected = server;
                let Some(replacement) = create_replacement_pipe(&installation.owner_sid, &shutdown).await? else {
                    drop(connected);
                    break;
                };
                server = replacement;
                let context = installation.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_client(connected, context).await {
                        eprintln!("[helper-pipe] rejected/failed client: {error:#}");
                    }
                });
            }
            _ = tick.tick() => drop(permit),
        }
    }
    drop(server);
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                eprintln!("[helper-pipe] client worker join failed during drain: {error}");
            }
        }
    };
    if tokio::time::timeout(RPC_DRAIN_TIMEOUT, drain)
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        bail!("pipe workers did not drain within {RPC_DRAIN_TIMEOUT:?}");
    }
    Ok(())
}

fn is_transient_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|code| code as u32),
        Some(
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_OPERATION_ABORTED | ERROR_PIPE_NOT_CONNECTED
        )
    )
}

async fn create_replacement_pipe(
    owner_sid: &str,
    shutdown: &AtomicBool,
) -> Result<Option<NamedPipeServer>> {
    loop {
        match create_pipe(false, owner_sid) {
            Ok(server) => return Ok(Some(server)),
            Err(error) if is_transient_capacity_error(&error) => {
                if shutdown.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_transient_capacity_error(error: &anyhow::Error) -> bool {
    let Some(io) = error.downcast_ref::<std::io::Error>() else {
        return false;
    };
    matches!(
        io.raw_os_error().map(|code| code as u32),
        Some(
            ERROR_PIPE_BUSY
                | ERROR_NOT_ENOUGH_MEMORY
                | ERROR_NO_SYSTEM_RESOURCES
                | ERROR_TOO_MANY_OPEN_FILES
        )
    )
}

async fn handle_client(pipe: NamedPipeServer, installation: Arc<Installation>) -> Result<()> {
    // Keep this guard alive through dispatch to prevent a PID-reuse race.
    let authenticated = security::authenticate_client(&pipe, &installation)
        .context("pipe client authentication failed")?;

    let (read_half, mut write_half) = tokio::io::split(pipe);
    let mut reader = BufReader::new(read_half).take((MAX_REQUEST_BYTES + 1) as u64);
    let mut payload = Vec::new();
    let read = tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut payload))
        .await
        .context("request read timeout")??;
    if read == 0 {
        bail!("client closed without a request");
    }
    if payload.len() > MAX_REQUEST_BYTES {
        bail!("request exceeds {MAX_REQUEST_BYTES} bytes");
    }
    if payload.last() != Some(&b'\n') {
        bail!("request is not newline terminated");
    }
    payload.pop();
    if payload.last() == Some(&b'\r') {
        payload.pop();
    }
    let request: Request = serde_json::from_slice(&payload).context("invalid JSON request")?;

    // Commands own their safe timeouts. Do not cancel a WFP transaction from
    // the outside: spawn_blocking work would continue after cancellation and
    // could install filters after the client has received an error.
    let response = dispatch::handle(request, &installation, &authenticated).await;
    send_response(&mut write_half, &response).await?;
    // Exactly one request per connection.
    write_half.shutdown().await.ok();
    Ok(())
}

async fn send_response<W: AsyncWriteExt + Unpin>(w: &mut W, resp: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(resp)?;
    bytes.push(b'\n');
    tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&bytes))
        .await
        .context("response write timeout")??;
    tokio::time::timeout(WRITE_TIMEOUT, w.flush())
        .await
        .context("response flush timeout")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_limit_is_bounded() {
        assert!(MAX_REQUEST_BYTES <= 1536 * 1024);
        assert!(MAX_INSTANCES <= 4);
        assert_eq!(MAX_CLIENT_WORKERS + 1, MAX_INSTANCES);
        assert!(RPC_DRAIN_TIMEOUT <= Duration::from_secs(15));
    }

    #[test]
    fn pipe_capacity_errors_are_retryable() {
        for code in [
            ERROR_PIPE_BUSY,
            ERROR_NOT_ENOUGH_MEMORY,
            ERROR_NO_SYSTEM_RESOURCES,
            ERROR_TOO_MANY_OPEN_FILES,
        ] {
            let error = anyhow::Error::from(std::io::Error::from_raw_os_error(code as i32));
            assert!(is_transient_capacity_error(&error));
        }
        for code in [
            ERROR_BROKEN_PIPE,
            ERROR_NO_DATA,
            ERROR_OPERATION_ABORTED,
            ERROR_PIPE_NOT_CONNECTED,
        ] {
            assert!(is_transient_accept_error(
                &std::io::Error::from_raw_os_error(code as i32)
            ));
        }
    }
}
