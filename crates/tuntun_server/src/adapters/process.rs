use std::process::Stdio;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use tuntun_core::{Error, ProcessExit, ProcessExitCode, ProcessPort, ProcessSpec, Result};

#[derive(Debug, Default)]
pub struct TokioProcess;

#[async_trait]
impl ProcessPort for TokioProcess {
    async fn run_to_completion(&self, spec: &ProcessSpec) -> Result<ProcessExit> {
        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        if let Some(dir) = &spec.working_dir {
            cmd.current_dir(dir);
        }
        cmd.stdin(if spec.stdin_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::port("process", format!("spawn {}: {e}", spec.program)))?;

        if let Some(input) = &spec.stdin_input {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(input)
                    .await
                    .map_err(|e| Error::port("process", format!("write stdin: {e}")))?;
                stdin
                    .shutdown()
                    .await
                    .map_err(|e| Error::port("process", format!("close stdin: {e}")))?;
            }
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| Error::port("process", format!("wait: {e}")))?;

        Ok(ProcessExit {
            code: output.status.code().map(ProcessExitCode),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
