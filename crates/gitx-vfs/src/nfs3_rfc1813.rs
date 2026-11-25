//! RFC 1813 NFSv3 + MOUNTv3 over RFC 5531 ONC-RPC v2 TCP loopback virtual filesystem server.
//!
//! Binds strictly to `127.0.0.1` and serves a demand-paged [`LazyWorkspace`] via [`FuseCore`]
//! using standard XDR binary framing and ONC-RPC Record Marking (`0x8000_0000 | len`), enabling
//! kernel-native mounts on macOS (`mount_nfs -o nolocks,vers=3,tcp,port=<p>,mountport=<p> 127.0.0.1:/ <mnt>`)
//! and Linux without FUSE or kernel extensions.

use crate::fuse_mount::{FuseCore, ROOT_INO, VfsAttr, VfsFileType};
use crate::lazy::{LazyStats, LazyWorkspace};
use gitx_core::{DomainId, DomainTree, GitxError, Result};
use gitx_store::ObjectStore;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ONC-RPC v2 constants (RFC 5531)
pub const RPC_VERSION: u32 = 2;
const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const REPLY_MSG_ACCEPTED: u32 = 0;
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_UNAVAIL: u32 = 1;
const ACCEPT_PROG_MISMATCH: u32 = 2;
const ACCEPT_PROC_UNAVAIL: u32 = 3;
const ACCEPT_GARBAGE_ARGS: u32 = 4;
const AUTH_NONE: u32 = 0;
const AUTH_SYS: u32 = 1;

// Program & version numbers (RFC 1813)
pub const NFS_PROGRAM: u32 = 100_003;
pub const NFS_V3: u32 = 3;
pub const MOUNT_PROGRAM: u32 = 100_005;
pub const MOUNT_V3: u32 = 3;

// MOUNTv3 procedure numbers
pub const MOUNTPROC3_NULL: u32 = 0;
pub const MOUNTPROC3_MNT: u32 = 1;
pub const MOUNTPROC3_DUMP: u32 = 2;
pub const MOUNTPROC3_UMNT: u32 = 3;
pub const MOUNTPROC3_UMNTALL: u32 = 4;
pub const MOUNTPROC3_EXPORT: u32 = 5;

// NFSv3 procedure numbers
pub const NFSPROC3_NULL: u32 = 0;
pub const NFSPROC3_GETATTR: u32 = 1;
pub const NFSPROC3_SETATTR: u32 = 2;
pub const NFSPROC3_LOOKUP: u32 = 3;
pub const NFSPROC3_ACCESS: u32 = 4;
pub const NFSPROC3_READLINK: u32 = 5;
pub const NFSPROC3_READ: u32 = 6;
pub const NFSPROC3_WRITE: u32 = 7;
pub const NFSPROC3_CREATE: u32 = 8;
pub const NFSPROC3_MKDIR: u32 = 9;
pub const NFSPROC3_SYMLINK: u32 = 10;
pub const NFSPROC3_REMOVE: u32 = 12;
pub const NFSPROC3_RMDIR: u32 = 13;
pub const NFSPROC3_RENAME: u32 = 14;
pub const NFSPROC3_READDIR: u32 = 16;
pub const NFSPROC3_READDIRPLUS: u32 = 17;
pub const NFSPROC3_FSSTAT: u32 = 18;
pub const NFSPROC3_FSINFO: u32 = 19;
pub const NFSPROC3_PATHCONF: u32 = 20;
pub const NFSPROC3_COMMIT: u32 = 21;

// NFSv3 status codes (RFC 1813 Section 2.6)
pub const NFS3_OK: u32 = 0;
const NFS3ERR_PERM: u32 = 1;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_ACCES: u32 = 13;
const NFS3ERR_EXIST: u32 = 17;
const NFS3ERR_NOTDIR: u32 = 20;
const NFS3ERR_ISDIR: u32 = 21;
const NFS3ERR_INVAL: u32 = 22;
const NFS3ERR_FBIG: u32 = 27;
const NFS3ERR_NAMETOOLONG: u32 = 63;
const NFS3ERR_NOTEMPTY: u32 = 66;
const NFS3ERR_STALE: u32 = 70;
const NFS3ERR_NOTSUPP: u32 = 10004;

// NFSv3 file types (ftype3)
const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;
const NF3LNK: u32 = 5;

// NFSv3 write stability
const FILE_SYNC: u32 = 2;

// Limits
const MAX_RPC_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 64;
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_VERF: [u8; 8] = *b"GITXNFS3";
const COOKIE_VERF: [u8; 8] = *b"GITXDIR3";
const MAX_RW_SIZE: u32 = 1024 * 1024;
const PREF_RW_SIZE: u32 = 65_536;

/// Returns the standard `mount_nfs` CLI arguments for mounting this loopback NFSv3 server on macOS.
pub fn macos_mount_nfs_args(port: u16, mountpoint: &Path) -> Vec<String> {
    vec![
        "-o".to_string(),
        format!("nolocks,vers=3,tcp,rsize=65536,wsize=65536,port={port},mountport={port}"),
        "127.0.0.1:/".to_string(),
        mountpoint.to_string_lossy().into_owned(),
    ]
}

/// Real RFC 1813 NFSv3 + MOUNTv3 server over ONC-RPC v2 TCP loopback (`127.0.0.1`).
///
/// Serves both `MOUNT` (program 100005 v3) and `NFS` (program 100003 v3) multiplexed on a
/// single loopback TCP port, backed by [`FuseCore`] and demand-paged [`LazyWorkspace`].
pub struct Nfs3LoopbackServer {
    addr: SocketAddr,
    core: Arc<Mutex<FuseCore>>,
    shutdown: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl Nfs3LoopbackServer {
    /// Start an RFC 1813 NFSv3 + MOUNTv3 server bound strictly to a loopback address
    /// (e.g. `"127.0.0.1:0"`).
    pub fn start(
        bind_addr: &str,
        workspace: LazyWorkspace,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        let addr = listener.local_addr()?;
        if !addr.ip().is_loopback() {
            return Err(GitxError::Workspace(format!(
                "refusing to bind unauthenticated Nfs3LoopbackServer to non-loopback address {addr}"
            )));
        }

        let core = Arc::new(Mutex::new(FuseCore::new(workspace, store)));
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_clients = Arc::new(AtomicUsize::new(0));

        let core_clone = Arc::clone(&core);
        let shutdown_clone = Arc::clone(&shutdown);
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
                            handle_onc_rpc_connection(stream, conn_core, conn_shutdown);
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

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
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

    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Nfs3LoopbackServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn handle_onc_rpc_connection(
    mut stream: TcpStream,
    core: Arc<Mutex<FuseCore>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        let msg = match read_rpc_record(&mut stream) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        if msg.is_empty() {
            break;
        }
        let Some(reply) = dispatch_onc_rpc(&core, &msg) else {
            break;
        };
        if write_rpc_record(&mut stream, &reply).is_err() {
            break;
        }
    }
}

fn dispatch_onc_rpc(core: &Arc<Mutex<FuseCore>>, raw: &[u8]) -> Option<Vec<u8>> {
    let mut r = XdrReader::new(raw);
    let xid = r.read_u32().ok()?;
    let mtype = r.read_u32().ok()?;
    if mtype != MSG_CALL {
        return None;
    }
    let rpcvers = r.read_u32().ok()?;
    if rpcvers != RPC_VERSION {
        let mut w = XdrWriter::new();
        w.write_u32(xid);
        w.write_u32(MSG_REPLY);
        w.write_u32(1); // MSG_DENIED
        w.write_u32(0); // RPC_MISMATCH
        w.write_u32(RPC_VERSION);
        w.write_u32(RPC_VERSION);
        return Some(w.into_bytes());
    }

    let prog = r.read_u32().ok()?;
    let vers = r.read_u32().ok()?;
    let proc_num = r.read_u32().ok()?;

    // Skip cred & verf opaque_auth structs
    let _cred_flavor = r.read_u32().ok()?;
    let _cred_body = r.read_opaque().ok()?;
    let _verf_flavor = r.read_u32().ok()?;
    let _verf_body = r.read_opaque().ok()?;

    let mut w = XdrWriter::new();
    w.write_u32(xid);
    w.write_u32(MSG_REPLY);
    w.write_u32(REPLY_MSG_ACCEPTED);
    // verifier: AUTH_NONE, 0 bytes
    w.write_u32(AUTH_NONE);
    w.write_u32(0);

    match prog {
        MOUNT_PROGRAM => {
            if vers != MOUNT_V3 {
                w.write_u32(ACCEPT_PROG_MISMATCH);
                w.write_u32(MOUNT_V3);
                w.write_u32(MOUNT_V3);
                return Some(w.into_bytes());
            }
            dispatch_mount_v3(proc_num, &mut r, &mut w);
        }
        NFS_PROGRAM => {
            if vers != NFS_V3 {
                w.write_u32(ACCEPT_PROG_MISMATCH);
                w.write_u32(NFS_V3);
                w.write_u32(NFS_V3);
                return Some(w.into_bytes());
            }
            let mut guard = core.lock().unwrap_or_else(|e| e.into_inner());
            dispatch_nfs_v3(&mut guard, proc_num, &mut r, &mut w);
        }
        _ => {
            w.write_u32(ACCEPT_PROG_UNAVAIL);
        }
    }

    Some(w.into_bytes())
}

fn dispatch_mount_v3(proc_num: u32, r: &mut XdrReader<'_>, w: &mut XdrWriter) {
    match proc_num {
        MOUNTPROC3_NULL => {
            w.write_u32(ACCEPT_SUCCESS);
        }
        MOUNTPROC3_MNT => {
            if r.read_string().is_err() {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            }
            w.write_u32(ACCEPT_SUCCESS);
            w.write_u32(NFS3_OK); // MNT3_OK
            write_fh3(w, ROOT_INO);
            // auth_flavors<>, advertise AUTH_NONE & AUTH_SYS
            w.write_u32(2);
            w.write_u32(AUTH_NONE);
            w.write_u32(AUTH_SYS);
        }
        MOUNTPROC3_DUMP => {
            w.write_u32(ACCEPT_SUCCESS);
            w.write_u32(0); // NULL mountlist
        }
        MOUNTPROC3_UMNT => {
            if r.read_string().is_err() {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            }
            w.write_u32(ACCEPT_SUCCESS);
        }
        MOUNTPROC3_UMNTALL => {
            w.write_u32(ACCEPT_SUCCESS);
        }
        MOUNTPROC3_EXPORT => {
            w.write_u32(ACCEPT_SUCCESS);
            // Single export entry: "/" with empty groups list (all loopback clients allowed)
            w.write_u32(1); // value follows
            w.write_string("/");
            w.write_u32(0); // ex_groups = NULL
            w.write_u32(0); // next = NULL
        }
        _ => {
            w.write_u32(ACCEPT_PROC_UNAVAIL);
        }
    }
}

fn dispatch_nfs_v3(core: &mut FuseCore, proc_num: u32, r: &mut XdrReader<'_>, w: &mut XdrWriter) {
    match proc_num {
        NFSPROC3_NULL => {
            w.write_u32(ACCEPT_SUCCESS);
        }
        NFSPROC3_GETATTR => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            match core.getattr(ino) {
                Ok(attr) => {
                    w.write_u32(NFS3_OK);
                    write_fattr3(w, &attr);
                }
                Err(code) => w.write_u32(errno_to_nfs3(code)),
            }
        }
        NFSPROC3_SETATTR => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(sattr) = read_sattr3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            // guard: sattrguard3 (check: bool, optional nfstime3)
            let Ok(check) = r.read_bool() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            if check && (r.read_u32().is_err() || r.read_u32().is_err()) {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            }
            w.write_u32(ACCEPT_SUCCESS);
            let pre = core.getattr(ino).ok();
            match core.setattr(ino, sattr.mode, sattr.size) {
                Ok(post) => {
                    w.write_u32(NFS3_OK);
                    write_wcc_data(w, pre.as_ref(), Some(&post));
                }
                Err(code) => {
                    let post = core.getattr(ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre.as_ref(), post.as_ref());
                }
            }
        }
        NFSPROC3_LOOKUP => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            match core.lookup(dir_ino, &name) {
                Ok(obj_attr) => {
                    let dir_attr = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_fh3(w, obj_attr.ino);
                    write_post_op_attr(w, Some(&obj_attr));
                    write_post_op_attr(w, dir_attr.as_ref());
                }
                Err(code) => {
                    let dir_attr = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, dir_attr.as_ref());
                }
            }
        }
        NFSPROC3_ACCESS => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(access_bits) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            match core.getattr(ino) {
                Ok(attr) => {
                    w.write_u32(NFS3_OK);
                    write_post_op_attr(w, Some(&attr));
                    w.write_u32(access_bits);
                }
                Err(code) => {
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, None);
                }
            }
        }
        NFSPROC3_READLINK => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let attr = core.getattr(ino).ok();
            match core.readlink(ino) {
                Ok(target) => {
                    w.write_u32(NFS3_OK);
                    write_post_op_attr(w, attr.as_ref());
                    w.write_opaque(&target);
                }
                Err(code) => {
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, attr.as_ref());
                }
            }
        }
        NFSPROC3_READ => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(offset) = r.read_u64() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(count) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            match core.read(ino, offset, count.min(MAX_RW_SIZE)) {
                Ok(data) => {
                    let attr = core.getattr(ino).ok();
                    let file_size = attr.as_ref().map(|a| a.size).unwrap_or(0);
                    let eof = offset.saturating_add(data.len() as u64) >= file_size;
                    w.write_u32(NFS3_OK);
                    write_post_op_attr(w, attr.as_ref());
                    w.write_u32(data.len() as u32);
                    w.write_bool(eof);
                    w.write_opaque(&data);
                }
                Err(code) => {
                    let attr = core.getattr(ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, attr.as_ref());
                }
            }
        }
        NFSPROC3_WRITE => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(offset) = r.read_u64() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(count) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_stable) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(data) = r.read_opaque() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre = core.getattr(ino).ok();
            let slice_len = (count as usize).min(data.len());
            match core.write(ino, offset, &data[..slice_len]) {
                Ok(written) => {
                    let post = core.getattr(ino).ok();
                    w.write_u32(NFS3_OK);
                    write_wcc_data(w, pre.as_ref(), post.as_ref());
                    w.write_u32(written);
                    w.write_u32(FILE_SYNC);
                    w.write_fixed(&WRITE_VERF);
                }
                Err(code) => {
                    let post = core.getattr(ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre.as_ref(), post.as_ref());
                }
            }
        }
        NFSPROC3_CREATE => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(createmode) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let sattr = match createmode {
                0 | 1 => match read_sattr3(r) {
                    Ok(s) => s,
                    Err(_) => {
                        w.write_u32(ACCEPT_GARBAGE_ARGS);
                        return;
                    }
                },
                2 => {
                    // EXCLUSIVE: 8-byte createverf3
                    if r.read_fixed(8).is_err() {
                        w.write_u32(ACCEPT_GARBAGE_ARGS);
                        return;
                    }
                    ParsedSattr3::default()
                }
                _ => {
                    w.write_u32(ACCEPT_GARBAGE_ARGS);
                    return;
                }
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre_dir = core.getattr(dir_ino).ok();
            let mode = sattr.mode.unwrap_or(0o644);
            let flags = if createmode == 1 || createmode == 2 {
                libc::O_EXCL
            } else {
                0
            };
            match core.create(dir_ino, &name, mode, flags) {
                Ok((obj_attr, _fh)) => {
                    let final_attr = if sattr.size.is_some() {
                        core.setattr(obj_attr.ino, sattr.mode, sattr.size)
                            .unwrap_or(obj_attr)
                    } else {
                        obj_attr
                    };
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_post_op_fh3(w, Some(final_attr.ino));
                    write_post_op_attr(w, Some(&final_attr));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
                Err(code) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
            }
        }
        NFSPROC3_MKDIR => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            if read_sattr3(r).is_err() {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            }
            w.write_u32(ACCEPT_SUCCESS);
            let pre_dir = core.getattr(dir_ino).ok();
            match core.mkdir(dir_ino, &name) {
                Ok(obj_attr) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_post_op_fh3(w, Some(obj_attr.ino));
                    write_post_op_attr(w, Some(&obj_attr));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
                Err(code) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
            }
        }
        NFSPROC3_SYMLINK => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            if read_sattr3(r).is_err() {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            }
            let Ok(target) = r.read_string() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre_dir = core.getattr(dir_ino).ok();
            match core.symlink(dir_ino, &name, &target) {
                Ok(obj_attr) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_post_op_fh3(w, Some(obj_attr.ino));
                    write_post_op_attr(w, Some(&obj_attr));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
                Err(code) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
            }
        }
        NFSPROC3_REMOVE => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre_dir = core.getattr(dir_ino).ok();
            match core.unlink(dir_ino, &name) {
                Ok(()) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
                Err(code) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
            }
        }
        NFSPROC3_RMDIR => {
            let Ok((dir_ino, name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre_dir = core.getattr(dir_ino).ok();
            match core.rmdir(dir_ino, &name) {
                Ok(()) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(NFS3_OK);
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
                Err(code) => {
                    let post_dir = core.getattr(dir_ino).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_dir.as_ref(), post_dir.as_ref());
                }
            }
        }
        NFSPROC3_RENAME => {
            let Ok((from_dir, from_name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok((to_dir, to_name)) = read_diropargs3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let pre_from = core.getattr(from_dir).ok();
            let pre_to = core.getattr(to_dir).ok();
            match core.rename(from_dir, &from_name, to_dir, &to_name, 0) {
                Ok(()) => {
                    let post_from = core.getattr(from_dir).ok();
                    let post_to = core.getattr(to_dir).ok();
                    w.write_u32(NFS3_OK);
                    write_wcc_data(w, pre_from.as_ref(), post_from.as_ref());
                    write_wcc_data(w, pre_to.as_ref(), post_to.as_ref());
                }
                Err(code) => {
                    let post_from = core.getattr(from_dir).ok();
                    let post_to = core.getattr(to_dir).ok();
                    w.write_u32(errno_to_nfs3(code));
                    write_wcc_data(w, pre_from.as_ref(), post_from.as_ref());
                    write_wcc_data(w, pre_to.as_ref(), post_to.as_ref());
                }
            }
        }
        NFSPROC3_READDIR => {
            let Ok(dir_ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(cookie) = r.read_u64() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_cookieverf) = r.read_fixed(8) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(count) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let dir_attr = core.getattr(dir_ino).ok();
            match core.readdir(dir_ino) {
                Ok(entries) => {
                    w.write_u32(NFS3_OK);
                    write_post_op_attr(w, dir_attr.as_ref());
                    w.write_fixed(&COOKIE_VERF);
                    let start = cookie as usize;
                    let max_bytes = (count as usize).max(256);
                    let start_len = w.len();
                    let mut emitted_all = true;
                    for (idx, entry) in entries.iter().enumerate().skip(start) {
                        let est = 24 + entry.name.len() + 4;
                        if w.len() - start_len + est > max_bytes && idx > start {
                            emitted_all = false;
                            break;
                        }
                        w.write_u32(1); // value follows
                        w.write_u64(entry.ino);
                        w.write_string(&entry.name);
                        w.write_u64((idx + 1) as u64); // next cookie
                    }
                    w.write_u32(0); // end of list
                    w.write_bool(emitted_all);
                }
                Err(code) => {
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, dir_attr.as_ref());
                }
            }
        }
        NFSPROC3_READDIRPLUS => {
            let Ok(dir_ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(cookie) = r.read_u64() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_cookieverf) = r.read_fixed(8) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_dircount) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(maxcount) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let dir_attr = core.getattr(dir_ino).ok();
            match core.readdir(dir_ino) {
                Ok(entries) => {
                    w.write_u32(NFS3_OK);
                    write_post_op_attr(w, dir_attr.as_ref());
                    w.write_fixed(&COOKIE_VERF);
                    let start = cookie as usize;
                    let max_bytes = (maxcount as usize).max(512);
                    let start_len = w.len();
                    let mut emitted_all = true;
                    for (idx, entry) in entries.iter().enumerate().skip(start) {
                        let est = 140 + entry.name.len();
                        if w.len() - start_len + est > max_bytes && idx > start {
                            emitted_all = false;
                            break;
                        }
                        let child_attr = core.getattr(entry.ino).ok();
                        w.write_u32(1); // value follows
                        w.write_u64(entry.ino);
                        w.write_string(&entry.name);
                        w.write_u64((idx + 1) as u64);
                        write_post_op_attr(w, child_attr.as_ref());
                        write_post_op_fh3(w, Some(entry.ino));
                    }
                    w.write_u32(0); // end of list
                    w.write_bool(emitted_all);
                }
                Err(code) => {
                    w.write_u32(errno_to_nfs3(code));
                    write_post_op_attr(w, dir_attr.as_ref());
                }
            }
        }
        NFSPROC3_FSSTAT => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let attr = core.getattr(ino).ok();
            let stats = core.stats();
            let total_bytes: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB virtual capacity
            let free_bytes = total_bytes / 2;
            let total_files = (stats.total_virtual_files as u64).saturating_add(1_000_000);
            w.write_u32(NFS3_OK);
            write_post_op_attr(w, attr.as_ref());
            w.write_u64(total_bytes); // tbytes
            w.write_u64(free_bytes); // fbytes
            w.write_u64(free_bytes); // abytes
            w.write_u64(total_files); // tfiles
            w.write_u64(1_000_000); // ffiles
            w.write_u64(1_000_000); // afiles
            w.write_u32(0); // invarsec
        }
        NFSPROC3_FSINFO => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let attr = core.getattr(ino).ok();
            w.write_u32(NFS3_OK);
            write_post_op_attr(w, attr.as_ref());
            w.write_u32(MAX_RW_SIZE); // rtmax
            w.write_u32(PREF_RW_SIZE); // rtpref
            w.write_u32(4096); // rtmult
            w.write_u32(MAX_RW_SIZE); // wtmax
            w.write_u32(PREF_RW_SIZE); // wtpref
            w.write_u32(4096); // wtmult
            w.write_u32(PREF_RW_SIZE); // dtpref
            w.write_u64(64 * 1024 * 1024); // maxfilesize
            w.write_u32(0); // time_delta.seconds
            w.write_u32(1_000_000); // time_delta.nseconds
            // FSF3_SYMLINK (0x0002) | FSF3_HOMOGENEOUS (0x0008) | FSF3_CANSETTIME (0x0010)
            w.write_u32(0x0002 | 0x0008 | 0x0010);
        }
        NFSPROC3_PATHCONF => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let attr = core.getattr(ino).ok();
            w.write_u32(NFS3_OK);
            write_post_op_attr(w, attr.as_ref());
            w.write_u32(1); // linkmax
            w.write_u32(255); // name_max
            w.write_bool(true); // no_trunc
            w.write_bool(true); // chown_restricted
            w.write_bool(false); // case_insensitive
            w.write_bool(true); // case_preserving
        }
        NFSPROC3_COMMIT => {
            let Ok(ino) = read_fh3(r) else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_offset) = r.read_u64() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            let Ok(_count) = r.read_u32() else {
                w.write_u32(ACCEPT_GARBAGE_ARGS);
                return;
            };
            w.write_u32(ACCEPT_SUCCESS);
            let attr = core.getattr(ino).ok();
            w.write_u32(NFS3_OK);
            write_wcc_data(w, attr.as_ref(), attr.as_ref());
            w.write_fixed(&WRITE_VERF);
        }
        _ => {
            w.write_u32(ACCEPT_PROC_UNAVAIL);
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 1813 XDR Helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ParsedSattr3 {
    mode: Option<u32>,
    size: Option<u64>,
}

fn read_fh3(r: &mut XdrReader<'_>) -> io::Result<u64> {
    let bytes = r.read_opaque()?;
    if bytes.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nfs_fh3 length",
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(arr))
}

fn write_fh3(w: &mut XdrWriter, ino: u64) {
    w.write_opaque(&ino.to_be_bytes());
}

fn write_post_op_fh3(w: &mut XdrWriter, ino: Option<u64>) {
    match ino {
        Some(i) => {
            w.write_u32(1);
            write_fh3(w, i);
        }
        None => w.write_u32(0),
    }
}

fn read_diropargs3(r: &mut XdrReader<'_>) -> io::Result<(u64, String)> {
    let dir_ino = read_fh3(r)?;
    let name = r.read_string()?;
    Ok((dir_ino, name))
}

fn read_sattr3(r: &mut XdrReader<'_>) -> io::Result<ParsedSattr3> {
    let mut out = ParsedSattr3::default();
    if r.read_bool()? {
        out.mode = Some(r.read_u32()?);
    }
    if r.read_bool()? {
        let _uid = r.read_u32()?;
    }
    if r.read_bool()? {
        let _gid = r.read_u32()?;
    }
    if r.read_bool()? {
        out.size = Some(r.read_u64()?);
    }
    // set_atime (0=DONT_CHANGE, 1=SET_TO_SERVER_TIME, 2=SET_TO_CLIENT_TIME)
    let atime_how = r.read_u32()?;
    if atime_how == 2 {
        let _ = r.read_u32()?;
        let _ = r.read_u32()?;
    }
    // set_mtime
    let mtime_how = r.read_u32()?;
    if mtime_how == 2 {
        let _ = r.read_u32()?;
        let _ = r.read_u32()?;
    }
    Ok(out)
}

fn write_fattr3(w: &mut XdrWriter, attr: &VfsAttr) {
    let ftype = match attr.kind {
        VfsFileType::RegularFile => NF3REG,
        VfsFileType::Directory => NF3DIR,
        VfsFileType::Symlink => NF3LNK,
    };
    let secs = attr.mtime_secs() as u32;
    let used = attr.size.div_ceil(4096) * 4096;
    w.write_u32(ftype); // type
    w.write_u32(attr.perm as u32); // mode
    w.write_u32(attr.nlink); // nlink
    w.write_u32(attr.uid); // uid
    w.write_u32(attr.gid); // gid
    w.write_u64(attr.size); // size
    w.write_u64(used); // used
    w.write_u32(0); // rdev.specdata1
    w.write_u32(0); // rdev.specdata2
    w.write_u64(1); // fsid
    w.write_u64(attr.ino); // fileid
    // atime, mtime, ctime (nfstime3: seconds u32, nseconds u32)
    w.write_u32(secs);
    w.write_u32(0);
    w.write_u32(secs);
    w.write_u32(0);
    w.write_u32(secs);
    w.write_u32(0);
}

fn write_post_op_attr(w: &mut XdrWriter, attr: Option<&VfsAttr>) {
    match attr {
        Some(a) => {
            w.write_u32(1);
            write_fattr3(w, a);
        }
        None => w.write_u32(0),
    }
}

fn write_wcc_data(w: &mut XdrWriter, pre: Option<&VfsAttr>, post: Option<&VfsAttr>) {
    match pre {
        Some(a) => {
            let secs = a.mtime_secs() as u32;
            w.write_u32(1); // pre_op_attr follows
            w.write_u64(a.size);
            w.write_u32(secs);
            w.write_u32(0);
            w.write_u32(secs);
            w.write_u32(0);
        }
        None => w.write_u32(0),
    }
    write_post_op_attr(w, post);
}

fn errno_to_nfs3(code: i32) -> u32 {
    match code {
        libc::EPERM => NFS3ERR_PERM,
        libc::ENOENT => NFS3ERR_NOENT,
        libc::EIO => NFS3ERR_IO,
        libc::EACCES => NFS3ERR_ACCES,
        libc::EEXIST => NFS3ERR_EXIST,
        libc::ENOTDIR => NFS3ERR_NOTDIR,
        libc::EISDIR => NFS3ERR_ISDIR,
        libc::EINVAL => NFS3ERR_INVAL,
        libc::EFBIG => NFS3ERR_FBIG,
        libc::ENAMETOOLONG => NFS3ERR_NAMETOOLONG,
        libc::ENOTEMPTY => NFS3ERR_NOTEMPTY,
        libc::ESTALE => NFS3ERR_STALE,
        libc::ENOSYS => NFS3ERR_NOTSUPP,
        _ => NFS3ERR_IO,
    }
}

// ---------------------------------------------------------------------------
// ONC-RPC Record Marking + XDR Reader / Writer
// ---------------------------------------------------------------------------

fn read_rpc_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && out.is_empty() => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        }
        let marker = u32::from_be_bytes(hdr);
        let is_last = (marker & 0x8000_0000) != 0;
        let frag_len = (marker & 0x7FFF_FFFF) as usize;
        if out.len().saturating_add(frag_len) > MAX_RPC_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ONC-RPC record exceeds maximum size",
            ));
        }
        let start = out.len();
        out.resize(start + frag_len, 0);
        stream.read_exact(&mut out[start..])?;
        if is_last {
            break;
        }
    }
    Ok(out)
}

fn write_rpc_record(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let marker = 0x8000_0000u32 | (payload.len() as u32);
    stream.write_all(&marker.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

pub struct XdrReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_u32(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "xdr u32 eof"));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> io::Result<u64> {
        let hi = self.read_u32()? as u64;
        let lo = self.read_u32()? as u64;
        Ok((hi << 32) | lo)
    }

    pub fn read_bool(&mut self) -> io::Result<bool> {
        Ok(self.read_u32()? != 0)
    }

    pub fn read_fixed(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let padded = len.next_multiple_of(4);
        if self.pos + padded > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "xdr fixed eof",
            ));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += padded;
        Ok(slice)
    }

    pub fn read_opaque(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if len > MAX_RPC_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xdr opaque too large",
            ));
        }
        Ok(self.read_fixed(len)?.to_vec())
    }

    pub fn read_string(&mut self) -> io::Result<String> {
        let bytes = self.read_opaque()?;
        String::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("xdr utf8: {e}")))
    }
}

pub struct XdrWriter {
    buf: Vec<u8>,
}

impl Default for XdrWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl XdrWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_bool(&mut self, v: bool) {
        self.write_u32(u32::from(v));
    }

    pub fn write_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        let rem = bytes.len() % 4;
        if rem != 0 {
            self.buf.extend(std::iter::repeat_n(0u8, 4 - rem));
        }
    }

    pub fn write_opaque(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.write_fixed(bytes);
    }

    pub fn write_string(&mut self, s: &str) {
        self.write_opaque(s.as_bytes());
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

// ---------------------------------------------------------------------------
// Standard ONC-RPC v2 / RFC 1813 Wire Client (for verification & tooling)
// ---------------------------------------------------------------------------

/// Minimal RFC 5531 / RFC 1813 TCP wire client for talking directly to [`Nfs3LoopbackServer`].
pub struct Nfs3WireClient {
    stream: TcpStream,
    next_xid: u32,
}

impl Nfs3WireClient {
    pub fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            next_xid: 1,
        })
    }

    /// Issue a raw ONC-RPC v2 call and return the accepted reply payload bytes.
    pub fn call(&mut self, prog: u32, vers: u32, proc_num: u32, args: &[u8]) -> Result<Vec<u8>> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1).max(1);

        let mut req = XdrWriter::new();
        req.write_u32(xid);
        req.write_u32(MSG_CALL);
        req.write_u32(RPC_VERSION);
        req.write_u32(prog);
        req.write_u32(vers);
        req.write_u32(proc_num);
        // AUTH_NONE cred + verf
        req.write_u32(AUTH_NONE);
        req.write_u32(0);
        req.write_u32(AUTH_NONE);
        req.write_u32(0);
        let mut raw = req.into_bytes();
        raw.extend_from_slice(args);

        write_rpc_record(&mut self.stream, &raw)?;
        let reply = read_rpc_record(&mut self.stream)?;
        let mut r = XdrReader::new(&reply);
        let reply_xid = r.read_u32()?;
        if reply_xid != xid {
            return Err(GitxError::Workspace(format!(
                "ONC-RPC xid mismatch: expected {xid}, got {reply_xid}"
            )));
        }
        let mtype = r.read_u32()?;
        let stat = r.read_u32()?;
        if mtype != MSG_REPLY || stat != REPLY_MSG_ACCEPTED {
            return Err(GitxError::Workspace(format!(
                "ONC-RPC call denied (mtype={mtype}, stat={stat})"
            )));
        }
        let _verf_flavor = r.read_u32()?;
        let _verf_body = r.read_opaque()?;
        let accept_stat = r.read_u32()?;
        if accept_stat != ACCEPT_SUCCESS {
            return Err(GitxError::Workspace(format!(
                "ONC-RPC accept_stat error: {accept_stat}"
            )));
        }
        Ok(reply[r.pos..].to_vec())
    }

    /// Execute `MOUNTPROC3_MNT` and return the root 8-byte NFSv3 file handle.
    pub fn mount(&mut self, export_path: &str) -> Result<Vec<u8>> {
        let mut args = XdrWriter::new();
        args.write_string(export_path);
        let resp = self.call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "MOUNT3 failed: status {status}"
            )));
        }
        Ok(r.read_opaque()?)
    }

    /// Execute `NFSPROC3_LOOKUP` inside `dir_fh` for `name`, returning the child file handle.
    pub fn lookup(&mut self, dir_fh: &[u8], name: &str) -> Result<Vec<u8>> {
        let mut args = XdrWriter::new();
        args.write_opaque(dir_fh);
        args.write_string(name);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_LOOKUP, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::NotFound(format!(
                "NFS3 LOOKUP '{name}' failed: status {status}"
            )));
        }
        Ok(r.read_opaque()?)
    }

    /// Execute `NFSPROC3_READ` on `fh`.
    pub fn read(&mut self, fh: &[u8], offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        let mut args = XdrWriter::new();
        args.write_opaque(fh);
        args.write_u64(offset);
        args.write_u32(count);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_READ, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 READ failed: status {status}"
            )));
        }
        skip_post_op_attr(&mut r)?;
        let _read_count = r.read_u32()?;
        let eof = r.read_bool()?;
        let data = r.read_opaque()?;
        Ok((data, eof))
    }

    /// Execute `NFSPROC3_CREATE` (UNCHECKED) in `dir_fh`, returning the newly created file handle.
    pub fn create(&mut self, dir_fh: &[u8], name: &str, mode: u32) -> Result<Vec<u8>> {
        let mut args = XdrWriter::new();
        args.write_opaque(dir_fh);
        args.write_string(name);
        args.write_u32(0); // UNCHECKED
        // sattr3: set mode only
        args.write_bool(true);
        args.write_u32(mode);
        args.write_bool(false); // uid
        args.write_bool(false); // gid
        args.write_bool(false); // size
        args.write_u32(0); // atime
        args.write_u32(0); // mtime
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_CREATE, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 CREATE '{name}' failed: status {status}"
            )));
        }
        let has_fh = r.read_bool()?;
        if !has_fh {
            return Err(GitxError::Workspace(
                "NFS3 CREATE returned no file handle".into(),
            ));
        }
        Ok(r.read_opaque()?)
    }

    /// Execute `NFSPROC3_WRITE` on `fh`.
    pub fn write(&mut self, fh: &[u8], offset: u64, data: &[u8]) -> Result<u32> {
        let mut args = XdrWriter::new();
        args.write_opaque(fh);
        args.write_u64(offset);
        args.write_u32(data.len() as u32);
        args.write_u32(FILE_SYNC);
        args.write_opaque(data);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_WRITE, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 WRITE failed: status {status}"
            )));
        }
        skip_wcc_data(&mut r)?;
        Ok(r.read_u32()?)
    }

    /// Execute `NFSPROC3_READDIR` on `dir_fh` and return entry names.
    pub fn readdir(&mut self, dir_fh: &[u8]) -> Result<Vec<String>> {
        let mut args = XdrWriter::new();
        args.write_opaque(dir_fh);
        args.write_u64(0);
        args.write_fixed(&[0u8; 8]);
        args.write_u32(65_536);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_READDIR, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 READDIR failed: status {status}"
            )));
        }
        skip_post_op_attr(&mut r)?;
        let _verf = r.read_fixed(8)?;
        let mut names = Vec::new();
        while r.read_bool()? {
            let _fileid = r.read_u64()?;
            names.push(r.read_string()?);
            let _cookie = r.read_u64()?;
        }
        Ok(names)
    }

    /// Execute `NFSPROC3_REMOVE` in `dir_fh`.
    pub fn remove(&mut self, dir_fh: &[u8], name: &str) -> Result<()> {
        let mut args = XdrWriter::new();
        args.write_opaque(dir_fh);
        args.write_string(name);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_REMOVE, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 REMOVE '{name}' failed: status {status}"
            )));
        }
        Ok(())
    }

    /// Execute `NFSPROC3_MKDIR` in `dir_fh`, returning the directory file handle.
    pub fn mkdir(&mut self, dir_fh: &[u8], name: &str) -> Result<Vec<u8>> {
        let mut args = XdrWriter::new();
        args.write_opaque(dir_fh);
        args.write_string(name);
        args.write_bool(false);
        args.write_bool(false);
        args.write_bool(false);
        args.write_bool(false);
        args.write_u32(0);
        args.write_u32(0);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_MKDIR, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 MKDIR '{name}' failed: status {status}"
            )));
        }
        let has_fh = r.read_bool()?;
        if !has_fh {
            return Err(GitxError::Workspace(
                "NFS3 MKDIR returned no file handle".into(),
            ));
        }
        Ok(r.read_opaque()?)
    }

    /// Execute `NFSPROC3_RENAME`.
    pub fn rename(
        &mut self,
        from_dir: &[u8],
        from_name: &str,
        to_dir: &[u8],
        to_name: &str,
    ) -> Result<()> {
        let mut args = XdrWriter::new();
        args.write_opaque(from_dir);
        args.write_string(from_name);
        args.write_opaque(to_dir);
        args.write_string(to_name);
        let resp = self.call(NFS_PROGRAM, NFS_V3, NFSPROC3_RENAME, &args.into_bytes())?;
        let mut r = XdrReader::new(&resp);
        let status = r.read_u32()?;
        if status != NFS3_OK {
            return Err(GitxError::Workspace(format!(
                "NFS3 RENAME failed: status {status}"
            )));
        }
        Ok(())
    }
}

fn skip_post_op_attr(r: &mut XdrReader<'_>) -> io::Result<()> {
    if r.read_bool()? {
        // fattr3 is fixed 84 bytes (21 * 4 bytes)
        let _ = r.read_fixed(84)?;
    }
    Ok(())
}

fn skip_wcc_data(r: &mut XdrReader<'_>) -> io::Result<()> {
    if r.read_bool()? {
        // wcc_attr is 24 bytes (size u64 + mtime 8 + ctime 8)
        let _ = r.read_fixed(24)?;
    }
    skip_post_op_attr(r)
}
