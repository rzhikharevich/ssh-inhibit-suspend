use std::collections::HashSet;
use std::process::ExitCode;

use futures_lite::StreamExt;
use tokio::signal::unix::SignalKind;
use zbus::zvariant::{OwnedFd, OwnedObjectPath};

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    gen_blocking = false
)]
trait LoginManager {
    fn list_sessions(&self) -> zbus::Result<Vec<(String, u32, String, String, OwnedObjectPath)>>;

    fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> zbus::Result<OwnedFd>;

    #[zbus(signal)]
    fn session_new(
        &self,
        session_id: &str,
        object_path: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn session_removed(
        &self,
        session_id: &str,
        object_path: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1",
    gen_blocking = false
)]
trait LoginSession {
    #[zbus(property)]
    fn remote(&self) -> zbus::Result<bool>;
}

async fn acquire_inhibitor(manager: &LoginManagerProxy<'_>) -> zbus::Result<OwnedFd> {
    manager.inhibit("sleep", "ssh-inhibit-suspend", "Remote session(s) active", "block").await
}

async fn run() -> zbus::Result<()> {
    let connection = zbus::Connection::system().await?;
    let manager = LoginManagerProxy::new(&connection).await?;

    let mut remote_sessions: HashSet<String> = HashSet::new();
    let mut inhibitor: Option<OwnedFd> = None;

    // Subscribe to signals BEFORE enumerating to avoid race conditions.
    let mut new_stream = manager.receive_session_new().await?;
    let mut removed_stream = manager.receive_session_removed().await?;

    // Enumerate existing sessions.
    for (session_id, _uid, _user, _seat, object_path) in manager.list_sessions().await? {
        let Ok(session) = LoginSessionProxy::builder(&connection).path(object_path)?.build().await
        else {
            eprintln!("warning: cannot open session {session_id}");
            continue;
        };
        match session.remote().await {
            Ok(true) => {
                remote_sessions.insert(session_id.clone());
                eprintln!("startup: session {session_id} is remote");
            }
            Ok(false) => {}
            Err(e) => eprintln!("warning: cannot check session {session_id}: {e}"),
        }
    }

    if remote_sessions.is_empty() {
        eprintln!("startup: no remote sessions");
    } else {
        inhibitor = Some(acquire_inhibitor(&manager).await?);
        eprintln!("startup: inhibitor acquired ({} remote session(s))", remote_sessions.len());
    }

    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())
        .expect("failed to register SIGINT handler");

    loop {
        tokio::select! {
            Some(signal) = new_stream.next() => {
                let args = signal.args()?;
                let session_id = args.session_id();
                let object_path = args.object_path();

                let Ok(session) = LoginSessionProxy::builder(&connection)
                    .path(object_path)?
                    .build()
                    .await
                else {
                    eprintln!("warning: cannot open session {session_id}");
                    continue;
                };
                match session.remote().await {
                    Ok(true) => {
                        remote_sessions.insert(session_id.to_string());
                        eprintln!(
                            "session {session_id}: remote, tracked (total: {})",
                            remote_sessions.len()
                        );
                        if inhibitor.is_none() {
                            inhibitor = Some(acquire_inhibitor(&manager).await?);
                            eprintln!("inhibitor acquired");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("warning: cannot check session {session_id}: {e}"),
                }
            }

            Some(signal) = removed_stream.next() => {
                let args = signal.args()?;
                let session_id = args.session_id();

                if remote_sessions.remove(*session_id) {
                    eprintln!(
                        "session {session_id}: removed (remaining: {})",
                        remote_sessions.len()
                    );
                    if remote_sessions.is_empty() {
                        inhibitor = None;
                        eprintln!("inhibitor released");
                    }
                }
            }

            _ = sigterm.recv() => {
                break;
            }

            _ = sigint.recv() => {
                break;
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    if std::env::args().len() > 1 {
        eprintln!("usage: ssh-inhibit-suspend");
        return ExitCode::FAILURE;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("failed to build tokio runtime");

    if let Err(e) = rt.block_on(run()) {
        eprintln!("fatal: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
