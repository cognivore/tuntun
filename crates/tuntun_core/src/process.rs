//! Subprocess value types used at the `ProcessPort` boundary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessSignal {
    Term,
    Hup,
    Int,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessExitCode(pub i32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpec {
    pub program: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    /// If `Some`, write these bytes to stdin before closing.
    #[serde(default)]
    pub stdin_input: Option<Vec<u8>>,
}

impl ProcessSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            working_dir: None,
            stdin_input: None,
        }
    }

    #[must_use]
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for a in args {
            self.args.push(a.into());
        }
        self
    }

    #[must_use]
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    #[must_use]
    pub fn working_dir(mut self, d: impl Into<String>) -> Self {
        self.working_dir = Some(d.into());
        self
    }

    #[must_use]
    pub fn stdin_input(mut self, bytes: Vec<u8>) -> Self {
        self.stdin_input = Some(bytes);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub code: Option<ProcessExitCode>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ProcessExit {
    pub fn is_success(&self) -> bool {
        matches!(self.code, Some(ProcessExitCode(0)))
    }

    pub fn stdout_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.stdout)
    }

    pub fn stderr_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.stderr)
    }
}
