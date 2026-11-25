use crate::fuse_mount::{FuseCore, VfsAttr, VfsDirEntry, VfsFileType};
use crate::lazy::{LazyStats, LazyWorkspace};
use gitx_core::{DomainId, DomainTree, GitxError, Result};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Maximum framed RPC payload size (64 MiB).
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Maximum concurrent loopback RPC client connections to prevent thread exhaustion.
const MAX_CONCURRENT_CLIENTS: usize = 64;

/// Per-socket read/write timeout on loopback RPC connections.
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Serializable NFSv3-style file attributes over the loopback RPC channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsAttr {
    pub ino: u64,
    pub kind: VfsFileType,
    pub size: u64,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_secs: u64,
}

impl From<VfsAttr> for NfsAttr {
    fn from(attr: VfsAttr) -> Self {
        Self {
            mtime_secs: attr.mtime_secs(),
            ino: attr.ino,
            kind: attr.kind,
            size: attr.size,
            perm: attr.perm,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
        }
    }
}

/// NFSv3-style RPC operations served by [`LoopbackVfsServer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NfsRpcRequest {
    GetAttr {
        fh: u64,
    },
    Lookup {
        dir_fh: u64,
        name: String,
    },
    ReadDir {
        dir_fh: u64,
    },
    Read {
        fh: u64,
        offset: u64,
        size: u32,
    },
    Write {
        fh: u64,
        offset: u64,
        data: Vec<u8>,
    },
    Create {
        dir_fh: u64,
        name: String,
        executable: bool,
    },
    SetAttr {
        fh: u64,
        size: Option<u64>,
        executable: Option<bool>,
    },
    Remove {
        dir_fh: u64,
        name: String,
    },
    Mkdir {
        dir_fh: u64,
        name: String,
    },
    Rmdir {
        dir_fh: u64,
        name: String,
    },
    Rename {
        old_dir_fh: u64,
        old_name: String,
        new_dir_fh: u64,
        new_name: String,
    },
    Snapshot {
        domain: String,
    },
    Stats,
}

/// Responses returned by [`LoopbackVfsServer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NfsRpcResponse {
    Attr(NfsAttr),
    DirEntries(Vec<VfsDirEntry>),
    Data(Vec<u8>),
    Written(u32),
    Ok,
    Tree(DomainTree),
    Stats(LazyStats),
    Error { code: i32, message: String },
}

/// Cross-platform TCP loopback virtual filesystem RPC server modeled on NFSv3 operations.
///
/// Serves a demand-paged [`LazyWorkspace`] + [`ObjectStore`] over `127.0.0.1` (typically
/// `127.0.0.1:0` for ephemeral port allocation), providing the non-FUSE / macOS loopback
/// virtual mount layer with identical CoW overlay and `O(dirty_files)` snapshot semantics.
pub struct LoopbackVfsServer {
    addr: SocketAddr,
    core: Arc<Mutex<FuseCore>>,
    shutdown: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl LoopbackVfsServer {
    /// Bind `bind_addr` (e.g. `"127.0.0.1:0"`) and spawn the background RPC accept loop.
    ///
    /// Strictly requires a loopback IP address (`127.0.0.1` / `::1`) because the loopback
    /// VFS RPC protocol is unauthenticated and intended only for local mount clients.
    pub fn start(
        bind_addr: &str,
        workspace: LazyWorkspace,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        let addr = listener.local_addr()?;
        if !addr.ip().is_loopback() {
            return Err(GitxError::Workspace(format!(
                "refusing to bind unauthenticated LoopbackVfsServer to non-loopback address {addr}"
            )));
        }
        let core = Arc::new(Mutex::new(FuseCore::new(workspace, store)));
        let shutdown = Arc::new(AtomicBool::new(false));

        let core_clone = Arc::clone(&core);
        let shutdown_clone = Arc::clone(&shutdown);
        let active_clients = Arc::new(AtomicUsize::new(0));
        let accept_thread = thread::spawn(move || {
            for incoming in listener.incoming() {
                if shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }
                match incoming {
                    Ok(stream) => {
                        let prev = active_clients.fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_CONCURRENT_CLIENTS {
                            active_clients.fetch_sub(1, Ordering::AcqRel);
                            drop(stream);
                            continue;
                        }
                        let _ = stream.set_nodelay(true);
                        let _ = stream.set_read_timeout(Some(SOCKET_IO_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(SOCKET_IO_TIMEOUT));
                        let conn_core = Arc::clone(&core_clone);
                        let conn_shutdown = Arc::clone(&shutdown_clone);
                        let conn_counter = Arc::clone(&active_clients);
                        thread::spawn(move || {
                            struct ActiveGuard(Arc<AtomicUsize>);
                            impl Drop for ActiveGuard {
                                fn drop(&mut self) {
                                    self.0.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let _guard = ActiveGuard(conn_counter);
                            handle_client_connection(stream, conn_core, conn_shutdown);
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            core,
            shutdown,
            accept_thread: Some(accept_thread),
        })
    }

    /// Return the bound TCP loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn core(&self) -> &Arc<Mutex<FuseCore>> {
        &self.core
    }

    pub fn stats(&self) -> LazyStats {
        self.core.lock().unwrap_or_else(|e| e.into_inner()).stats()
    }

    pub fn snapshot(&self, domain: DomainId) -> Result<DomainTree> {
        self.core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot(domain)
    }

    /// Stop the accept loop and join the background server thread cleanly.
    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock `listener.incoming()` with a loopback wakeup connection.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LoopbackVfsServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Persistent TCP client speaking the NFSv3-style loopback protocol to [`LoopbackVfsServer`].
pub struct LoopbackVfsClient {
    stream: TcpStream,
}

impl LoopbackVfsClient {
    pub fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    pub fn call(&mut self, req: &NfsRpcRequest) -> Result<NfsRpcResponse> {
        write_frame(&mut self.stream, req)?;
        read_frame(&mut self.stream)
    }

    pub fn getattr(&mut self, fh: u64) -> Result<NfsAttr> {
        match self.call(&NfsRpcRequest::GetAttr { fh })? {
            NfsRpcResponse::Attr(attr) => Ok(attr),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Attr", &other)),
        }
    }

    pub fn lookup(&mut self, dir_fh: u64, name: &str) -> Result<NfsAttr> {
        match self.call(&NfsRpcRequest::Lookup {
            dir_fh,
            name: name.to_string(),
        })? {
            NfsRpcResponse::Attr(attr) => Ok(attr),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Attr", &other)),
        }
    }

    pub fn readdir(&mut self, dir_fh: u64) -> Result<Vec<VfsDirEntry>> {
        match self.call(&NfsRpcRequest::ReadDir { dir_fh })? {
            NfsRpcResponse::DirEntries(entries) => Ok(entries),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("DirEntries", &other)),
        }
    }

    pub fn read(&mut self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>> {
        match self.call(&NfsRpcRequest::Read { fh, offset, size })? {
            NfsRpcResponse::Data(data) => Ok(data),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Data", &other)),
        }
    }

    pub fn write(&mut self, fh: u64, offset: u64, data: &[u8]) -> Result<u32> {
        match self.call(&NfsRpcRequest::Write {
            fh,
            offset,
            data: data.to_vec(),
        })? {
            NfsRpcResponse::Written(n) => Ok(n),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Written", &other)),
        }
    }

    pub fn create(&mut self, dir_fh: u64, name: &str, executable: bool) -> Result<NfsAttr> {
        match self.call(&NfsRpcRequest::Create {
            dir_fh,
            name: name.to_string(),
            executable,
        })? {
            NfsRpcResponse::Attr(attr) => Ok(attr),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Attr", &other)),
        }
    }

    pub fn setattr(
        &mut self,
        fh: u64,
        size: Option<u64>,
        executable: Option<bool>,
    ) -> Result<NfsAttr> {
        match self.call(&NfsRpcRequest::SetAttr {
            fh,
            size,
            executable,
        })? {
            NfsRpcResponse::Attr(attr) => Ok(attr),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Attr", &other)),
        }
    }

    pub fn remove(&mut self, dir_fh: u64, name: &str) -> Result<()> {
        match self.call(&NfsRpcRequest::Remove {
            dir_fh,
            name: name.to_string(),
        })? {
            NfsRpcResponse::Ok => Ok(()),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Ok", &other)),
        }
    }

    pub fn mkdir(&mut self, dir_fh: u64, name: &str) -> Result<NfsAttr> {
        match self.call(&NfsRpcRequest::Mkdir {
            dir_fh,
            name: name.to_string(),
        })? {
            NfsRpcResponse::Attr(attr) => Ok(attr),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Attr", &other)),
        }
    }

    pub fn rmdir(&mut self, dir_fh: u64, name: &str) -> Result<()> {
        match self.call(&NfsRpcRequest::Rmdir {
            dir_fh,
            name: name.to_string(),
        })? {
            NfsRpcResponse::Ok => Ok(()),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Ok", &other)),
        }
    }

    pub fn rename(
        &mut self,
        old_dir_fh: u64,
        old_name: &str,
        new_dir_fh: u64,
        new_name: &str,
    ) -> Result<()> {
        match self.call(&NfsRpcRequest::Rename {
            old_dir_fh,
            old_name: old_name.to_string(),
            new_dir_fh,
            new_name: new_name.to_string(),
        })? {
            NfsRpcResponse::Ok => Ok(()),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Ok", &other)),
        }
    }

    pub fn snapshot(&mut self, domain: DomainId) -> Result<DomainTree> {
        match self.call(&NfsRpcRequest::Snapshot {
            domain: domain.to_string(),
        })? {
            NfsRpcResponse::Tree(tree) => Ok(tree),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Tree", &other)),
        }
    }

    pub fn stats(&mut self) -> Result<LazyStats> {
        match self.call(&NfsRpcRequest::Stats)? {
            NfsRpcResponse::Stats(stats) => Ok(stats),
            NfsRpcResponse::Error { code, message } => Err(errno_to_gitx_err(code, message)),
            other => Err(unexpected_response("Stats", &other)),
        }
    }
}

fn handle_client_connection(
    mut stream: TcpStream,
    core: Arc<Mutex<FuseCore>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        let req: NfsRpcRequest = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(_) => break,
        };
        let resp = dispatch_rpc(&core, req);
        if write_frame(&mut stream, &resp).is_err() {
            break;
        }
    }
}

fn dispatch_rpc(core: &Arc<Mutex<FuseCore>>, req: NfsRpcRequest) -> NfsRpcResponse {
    let mut guard = core.lock().unwrap_or_else(|e| e.into_inner());
    match req {
        NfsRpcRequest::GetAttr { fh } => match guard.getattr(fh) {
            Ok(attr) => NfsRpcResponse::Attr(attr.into()),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Lookup { dir_fh, name } => match guard.lookup(dir_fh, &name) {
            Ok(attr) => NfsRpcResponse::Attr(attr.into()),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::ReadDir { dir_fh } => match guard.readdir(dir_fh) {
            Ok(entries) => NfsRpcResponse::DirEntries(entries),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Read { fh, offset, size } => match guard.read(fh, offset, size) {
            Ok(data) => NfsRpcResponse::Data(data),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Write { fh, offset, data } => match guard.write(fh, offset, &data) {
            Ok(n) => NfsRpcResponse::Written(n),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Create {
            dir_fh,
            name,
            executable,
        } => {
            let mode = if executable { 0o755 } else { 0o644 };
            match guard.create(dir_fh, &name, mode, libc::O_TRUNC) {
                Ok((attr, _fh)) => NfsRpcResponse::Attr(attr.into()),
                Err(code) => errno_response(code),
            }
        }
        NfsRpcRequest::SetAttr {
            fh,
            size,
            executable,
        } => {
            let mode = executable.map(|x| if x { 0o755 } else { 0o644 });
            match guard.setattr(fh, mode, size) {
                Ok(attr) => NfsRpcResponse::Attr(attr.into()),
                Err(code) => errno_response(code),
            }
        }
        NfsRpcRequest::Remove { dir_fh, name } => match guard.unlink(dir_fh, &name) {
            Ok(()) => NfsRpcResponse::Ok,
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Mkdir { dir_fh, name } => match guard.mkdir(dir_fh, &name) {
            Ok(attr) => NfsRpcResponse::Attr(attr.into()),
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Rmdir { dir_fh, name } => match guard.rmdir(dir_fh, &name) {
            Ok(()) => NfsRpcResponse::Ok,
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Rename {
            old_dir_fh,
            old_name,
            new_dir_fh,
            new_name,
        } => match guard.rename(old_dir_fh, &old_name, new_dir_fh, &new_name, 0) {
            Ok(()) => NfsRpcResponse::Ok,
            Err(code) => errno_response(code),
        },
        NfsRpcRequest::Snapshot { domain } => match DomainId::new(&domain) {
            Ok(dom) => match guard.snapshot(dom) {
                Ok(tree) => NfsRpcResponse::Tree(tree),
                Err(err) => NfsRpcResponse::Error {
                    code: libc::EIO,
                    message: err.to_string(),
                },
            },
            Err(err) => NfsRpcResponse::Error {
                code: libc::EINVAL,
                message: err.to_string(),
            },
        },
        NfsRpcRequest::Stats => NfsRpcResponse::Stats(guard.stats()),
    }
}

fn errno_response(code: i32) -> NfsRpcResponse {
    NfsRpcResponse::Error {
        code,
        message: io::Error::from_raw_os_error(code).to_string(),
    }
}

fn errno_to_gitx_err(code: i32, message: String) -> GitxError {
    if code == libc::ENOENT {
        GitxError::NotFound(message)
    } else if code == libc::EACCES {
        GitxError::AccessDenied {
            domain: "vfs".to_string(),
            reason: message,
        }
    } else {
        GitxError::Io(io::Error::from_raw_os_error(code))
    }
}

fn unexpected_response(expected: &str, got: &NfsRpcResponse) -> GitxError {
    GitxError::Workspace(format!(
        "unexpected loopback VFS RPC response (expected {expected}, got {got:?})"
    ))
}

fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value).map_err(|e| GitxError::Serialization(e.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(GitxError::Workspace(format!(
            "RPC frame too large: {} bytes",
            payload.len()
        )));
    }
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(GitxError::Workspace(format!(
            "incoming RPC frame exceeds maximum size ({len} bytes)"
        )));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| GitxError::Serialization(e.to_string()))
}
