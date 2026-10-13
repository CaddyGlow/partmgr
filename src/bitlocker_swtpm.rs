//! Experimental isolated swtpm lifecycle for explicitly imported persistent state.
//!
//! The source must belong to a stopped emulator. Importing persistent state does
//! not reconstruct measured boot, PCR values, volatile sessions, or authorization.
//! Firmware variables are not accepted as TPM state. Only the private copy is
//! opened by the child; the caller must coordinate all command-channel clients.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const PERMANENT: &str = "tpm2-00.permall";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

/// Explicit startup behavior for the newly owned emulator only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startup {
    /// Issue TPM2_Startup(CLEAR) to the imported copy. PCRs are cold-start values.
    Clear,
    /// Initialize swtpm's command interface but leave TPM2_Startup to the caller.
    Caller,
}

/// Inputs for a fresh private imported-state instance. No defaults select paths.
#[derive(Debug)]
pub struct ImportConfig<'a> {
    /// Explicit swtpm executable, either absolute or resolved by the caller's PATH.
    pub executable: &'a Path,
    /// Quiescent swtpm directory containing a regular `tpm2-00.permall` file.
    pub source_state: &'a Path,
    /// New directory; an existing path is always refused and never overwritten.
    pub instance_directory: &'a Path,
    /// Startup mutates only the disposable imported copy.
    pub startup: Startup,
    /// Maximum time to wait for startup and owned-process shutdown.
    pub timeout: Duration,
}

/// Owns one isolated emulator and its private copied state.
///
/// Call [`Self::shutdown`] after dropping all command transports. Drop makes a
/// bounded best-effort control shutdown, then kills only this owned child if
/// necessary. State and logs are retained for explicit caller cleanup.
pub struct ImportedSwtpm {
    child: Option<Child>,
    directory: PathBuf,
    command: PathBuf,
    control: PathBuf,
    timeout: Duration,
}

impl core::fmt::Debug for ImportedSwtpm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportedSwtpm")
            .field("running", &self.child.is_some())
            .finish_non_exhaustive()
    }
}

impl ImportedSwtpm {
    /// Copy a stopped TPM's persistent state and start an independent emulator.
    ///
    /// This does not establish that the copied state matches a protector or its
    /// PCR policy. Volatile state is deliberately not imported by this API.
    pub fn import(config: ImportConfig<'_>) -> io::Result<Self> {
        if config.timeout.is_zero() || config.timeout > Duration::from_secs(60) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "swtpm timeout must be in (0, 60s]",
            ));
        }
        let source = config.source_state.join(PERMANENT);
        let metadata = fs::symlink_metadata(&source)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_STATE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported swtpm permanent-state file",
            ));
        }
        // swtpm's comma-separated option syntax cannot safely represent commas.
        let directory = config.instance_directory.to_path_buf();
        let text = directory.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "swtpm instance path must be UTF-8",
            )
        })?;
        if !directory.is_absolute() || text.contains(',') || text.len() > 80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "swtpm instance path must be absolute, comma-free and at most 80 bytes",
            ));
        }
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let state = directory.join("state");
        fs::DirBuilder::new().mode(0o700).create(&state)?;
        let mut input = File::open(&source)?;
        let opened = input.metadata()?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "swtpm source was replaced before import",
            ));
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.join(PERMANENT))?;
        let copied = io::copy(&mut (&mut input).take(MAX_STATE_BYTES + 1), &mut output)?;
        let after = input.metadata()?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || copied != metadata.len()
            || after.len() != metadata.len()
            || after.modified()? != metadata.modified()?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "swtpm source changed while importing",
            ));
        }
        output.sync_all()?;
        let command = directory.join("command.sock");
        let control = directory.join("command.sock.ctrl");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("swtpm.log"))?;
        let child = Command::new(config.executable)
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={},mode=0600,lock,fsync", state.display()))
            .arg("--server")
            .arg(format!("type=unixio,path={},mode=0600", command.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={},mode=0600", control.display()))
            .arg("--flags")
            .arg(match config.startup {
                Startup::Clear => "not-need-init,startup-clear",
                Startup::Caller => "not-need-init,startup-none",
            })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()?;
        let mut instance = Self {
            child: Some(child),
            directory,
            command,
            control,
            timeout: config.timeout,
        };
        let deadline = Instant::now() + config.timeout;
        loop {
            if let Some(child) = instance.child.as_mut()
                && child.try_wait()?.is_some()
            {
                return Err(io::Error::other(
                    "swtpm exited during startup; inspect retained swtpm.log",
                ));
            }
            let ready = [&instance.command, &instance.control]
                .iter()
                .all(|path| fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()));
            if ready {
                return Ok(instance);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "swtpm startup timed out",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// TPM command socket, distinct from the emulator control interface.
    pub fn command_socket(&self) -> &Path {
        &self.command
    }

    /// Emulator control socket; never send raw TPM commands to this endpoint.
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    /// Private retained instance directory (contains sensitive copied state).
    pub fn instance_directory(&self) -> &Path {
        &self.directory
    }

    /// Shut down this owned emulator via its control protocol and reap it.
    ///
    /// Call only after dropping command clients. Failure retains an owned child
    /// for Drop's kill/reap fallback; it never signals any source emulator.
    pub fn shutdown(&mut self) -> io::Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        if child.try_wait()?.is_some() {
            self.child = None;
            return Ok(());
        }
        let mut control = UnixStream::connect(&self.control)?;
        control.set_read_timeout(Some(self.timeout))?;
        control.set_write_timeout(Some(self.timeout))?;
        // swtpm tpm_ioctl.h: big-endian CMD_SHUTDOWN = 3, response ptm_res.
        control.write_all(&3u32.to_be_bytes())?;
        let mut response = [0; 4];
        control.read_exact(&mut response)?;
        if response != [0; 4] {
            return Err(io::Error::other("swtpm control shutdown rejected"));
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            if child.try_wait()?.is_some() {
                self.child = None;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "swtpm shutdown timed out",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ImportedSwtpm {
    fn drop(&mut self) {
        // Bound cleanup independently of a larger caller-selected startup budget.
        self.timeout = self.timeout.min(Duration::from_millis(250));
        let _ = self.shutdown();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn config<'a>(source: &'a Path, target: &'a Path) -> ImportConfig<'a> {
        ImportConfig {
            executable: Path::new("/missing-partmgr-swtpm"),
            source_state: source,
            instance_directory: target,
            startup: Startup::Clear,
            timeout: Duration::from_millis(100),
        }
    }

    #[test]
    fn rejects_symlink_or_oversized_source_without_creating_target() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("source");
        fs::create_dir(&state).unwrap();
        let original = root.path().join("original");
        fs::write(&original, b"not TPM state").unwrap();
        symlink(&original, state.join(PERMANENT)).unwrap();
        let target = root.path().join("target");
        assert_eq!(
            ImportedSwtpm::import(config(&state, &target))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!target.exists());
        fs::remove_file(state.join(PERMANENT)).unwrap();
        File::create(state.join(PERMANENT))
            .unwrap()
            .set_len(MAX_STATE_BYTES + 1)
            .unwrap();
        assert_eq!(
            ImportedSwtpm::import(config(&state, &target))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!target.exists());
    }

    #[test]
    fn existing_destination_is_never_reused_and_original_is_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("source");
        fs::create_dir(&state).unwrap();
        fs::write(state.join(PERMANENT), b"state bytes").unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"keep").unwrap();
        assert_eq!(
            ImportedSwtpm::import(config(&state, &target))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
        assert_eq!(fs::read(state.join(PERMANENT)).unwrap(), b"state bytes");
    }

    #[test]
    fn rejects_ambiguous_paths_and_invalid_lifecycle_deadlines() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(PERMANENT), b"state bytes").unwrap();
        for target in [Path::new("relative"), Path::new("/tmp/comma,path")] {
            assert_eq!(
                ImportedSwtpm::import(config(root.path(), target))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let target = root.path().join("target");
        for timeout in [Duration::ZERO, Duration::from_secs(61)] {
            let mut options = config(root.path(), &target);
            options.timeout = timeout;
            assert_eq!(
                ImportedSwtpm::import(options).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(!target.exists());
    }

    #[test]
    fn executable_failure_leaves_private_copy_and_original_untouched() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("source");
        fs::create_dir(&state).unwrap();
        fs::write(state.join(PERMANENT), b"state bytes").unwrap();
        let target = root.path().join("target");
        assert_eq!(
            ImportedSwtpm::import(config(&state, &target))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(fs::read(state.join(PERMANENT)).unwrap(), b"state bytes");
        assert_eq!(
            fs::read(target.join("state").join(PERMANENT)).unwrap(),
            b"state bytes"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(target.join("state").join(PERMANENT))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
