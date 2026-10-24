//! Native process ownership only. RPC and authorization remain in their original layers.
use super::{ExecError, OwnedExecutorConfig};
use std::{io, process::ExitStatus};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

enum Process {
    #[cfg(not(target_os = "macos"))]
    Tokio(tokio::process::Child),
    #[cfg(target_os = "macos")]
    Darwin(crate::platform::macos_spawn::RunningChild),
}
pub(super) struct Child {
    process: Process,
    pub(super) stdin: Option<ChildStdin>,
    pub(super) stdout: Option<ChildStdout>,
    pub(super) stderr: Option<ChildStderr>,
}
impl Child {
    pub(super) fn spawn(config: &OwnedExecutorConfig) -> Result<Self, ExecError> {
        #[cfg(target_os = "macos")]
        {
            let _ = config;
            Err(ExecError::SpawnFailed)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let mut child = tokio::process::Command::new(&config.binary)
                .args(["exec-server", "--listen", "stdio://"])
                .current_dir(&config.cwd)
                .env_clear()
                .envs(&config.environment)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| ExecError::SpawnFailed)?;
            Ok(Self {
                stdin: child.stdin.take(),
                stdout: child.stdout.take(),
                stderr: child.stderr.take(),
                process: Process::Tokio(child),
            })
        }
    }
    #[cfg(target_os = "macos")]
    pub(super) async fn spawn_pinned(
        config: &OwnedExecutorConfig,
        image: std::sync::Arc<crate::store::PinnedExecutable>,
    ) -> Result<Self, ExecError> {
        let cwd = config.cwd.clone();
        let env = config
            .environment
            .iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        // The enclosing foreground job retains its original owner/leases while
        // this bounded startup runs. A dropped response never grants another owner.
        let spawned = tokio::task::spawn_blocking(move || {
            crate::platform::macos_spawn::spawn_suspended(
                image,
                vec!["exec-server".into(), "--listen".into(), "stdio://".into()],
                cwd,
                env,
            )
            .and_then(|child| child.verify_and_resume())
        })
        .await
        .map_err(|_| ExecError::ProcessLost)?;
        let mut child = match spawned {
            Ok(child) => child,
            Err(failure) => {
                if let Some(mut original) = failure.into_owned_child() {
                    original
                        .terminate_and_wait()
                        .await
                        .map_err(|_| ExecError::ProcessLost)?;
                }
                return Err(ExecError::SpawnFailed);
            }
        };
        Ok(Self {
            stdin: child.take_stdin(),
            stdout: child.take_stdout(),
            stderr: child.take_stderr(),
            process: Process::Darwin(child),
        })
    }
    pub(super) fn start_kill(&mut self) -> io::Result<()> {
        match &mut self.process {
            #[cfg(not(target_os = "macos"))]
            Process::Tokio(child) => child.start_kill(),
            #[cfg(target_os = "macos")]
            Process::Darwin(child) => child.start_kill(),
        }
    }
    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.process {
            #[cfg(not(target_os = "macos"))]
            Process::Tokio(child) => child.wait().await,
            #[cfg(target_os = "macos")]
            Process::Darwin(child) => child.wait().await,
        }
    }
    pub(super) async fn kill(&mut self) -> io::Result<()> {
        self.start_kill()?;
        self.wait().await.map(|_| ())
    }
}
