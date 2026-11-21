use crate::backend::{WorkspaceBackend, normalize_rel_path};
use crate::lazy::{LazyStats, LazyWorkspace};
use gitx_core::{DomainId, DomainTree, EntryKind, FileMode, GitxError, Result};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(target_os = "linux", feature = "fuse"))]
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};
#[cfg(all(target_os = "linux", feature = "fuse"))]
use std::ffi::OsStr;
#[cfg(all(target_os = "linux", feature = "fuse"))]
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "linux", feature = "fuse"))]
use std::sync::Mutex;
#[cfg(all(target_os = "linux", feature = "fuse"))]
use std::time::Duration;

/// Canonical root directory inode number for FUSE3 and NFSv3 mounts.
pub const ROOT_INO: u64 = 1;

/// Kernel attribute/entry cache TTL (zero ensures mutations are immediately visible).
#[cfg(all(target_os = "linux", feature = "fuse"))]
const TTL: Duration = Duration::ZERO;

/// Standard POSIX block size reported by virtual mounts.
const BLOCK_SIZE: u32 = 4096;

/// Linux `renameat2` `RENAME_NOREPLACE` flag.
const RENAME_NOREPLACE: u32 = 1;

/// Result alias returning POSIX errno codes (`libc::ENOENT`, `libc::EEXIST`, etc.).
pub type PosixResult<T> = std::result::Result<T, i32>;

/// Virtual file kind shared between the Linux FUSE3 backend and cross-platform loopback engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsFileType {
    Directory,
    RegularFile,
    Symlink,
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
impl From<VfsFileType> for FileType {
    fn from(kind: VfsFileType) -> Self {
        match kind {
            VfsFileType::Directory => FileType::Directory,
            VfsFileType::RegularFile => FileType::RegularFile,
            VfsFileType::Symlink => FileType::Symlink,
        }
    }
}

/// Platform-independent file attributes returned by [`FuseCore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsAttr {
    pub ino: u64,
    pub kind: VfsFileType,
    pub size: u64,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: SystemTime,
}

impl VfsAttr {
    /// Convert to a FUSE [`FileAttr`] on Linux.
    #[cfg(all(target_os = "linux", feature = "fuse"))]
    pub fn to_fuse_attr(&self) -> FileAttr {
        let blocks = self.size.div_ceil(512);
        FileAttr {
            ino: self.ino,
            size: self.size,
            blocks,
            atime: self.mtime,
            mtime: self.mtime,
            ctime: self.mtime,
            crtime: self.mtime,
            kind: self.kind.into(),
            perm: self.perm,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Modification time as seconds since the Unix epoch.
    pub fn mtime_secs(&self) -> u64 {
        self.mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Directory entry returned by [`FuseCore::readdir`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsDirEntry {
    pub ino: u64,
    pub name: String,
    pub kind: VfsFileType,
}

/// Core POSIX-compatible virtual filesystem state backed by a demand-paged [`LazyWorkspace`].
///
/// Maintains a dynamic bidirectional inode table (`ROOT_INO = 1`) over the virtual base
/// [`DomainTree`] plus Copy-on-Write sparse overlay files, tombstones, and explicit empty
/// directories. Base files are never written to disk and are hydrated lazily from the
/// [`ObjectStore`] only on read (or partial CoW write).
pub struct FuseCore {
    workspace: LazyWorkspace,
    store: Arc<dyn ObjectStore>,
    ino_to_path: BTreeMap<u64, String>,
    path_to_ino: BTreeMap<String, u64>,
    next_ino: u64,
    explicit_dirs: BTreeSet<String>,
    next_fh: u64,
    uid: u32,
    gid: u32,
    mtime: SystemTime,
}

impl FuseCore {
    /// Create a new [`FuseCore`] mounted over `workspace` and `store` in O(1) time.
    pub fn new(workspace: LazyWorkspace, store: Arc<dyn ObjectStore>) -> Self {
        let mut ino_to_path = BTreeMap::new();
        let mut path_to_ino = BTreeMap::new();
        ino_to_path.insert(ROOT_INO, String::new());
        path_to_ino.insert(String::new(), ROOT_INO);

        let (uid, gid) = current_uid_gid();
        Self {
            workspace,
            store,
            ino_to_path,
            path_to_ino,
            next_ino: ROOT_INO + 1,
            explicit_dirs: BTreeSet::new(),
            next_fh: 1,
            uid,
            gid,
            mtime: SystemTime::now(),
        }
    }

    pub fn workspace(&self) -> &LazyWorkspace {
        &self.workspace
    }

    pub fn store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    pub fn stats(&self) -> LazyStats {
        self.workspace.stats()
    }

    /// Produce an O(dirty_files) [`DomainTree`] snapshot of the virtual workspace.
    pub fn snapshot(&self, domain: DomainId) -> Result<DomainTree> {
        self.workspace.snapshot_tree(domain, self.store.as_ref())
    }

    /// Look up the currently allocated inode for a canonical relative path (`""` for root).
    pub fn resolve_inode(&self, path: &str) -> Option<u64> {
        self.path_to_ino.get(path).copied()
    }

    /// Look up the canonical relative path for an allocated inode (`""` for root).
    pub fn resolve_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(String::as_str)
    }

    /// Look up a single child entry `name` inside directory `parent`.
    pub fn lookup(&mut self, parent: u64, name: &str) -> PosixResult<VfsAttr> {
        let parent_path = self.require_dir_path(parent)?;
        if name == "." {
            return self.getattr(parent);
        }
        if name == ".." {
            let grand_ino = self.parent_ino_for_path(&parent_path);
            return self.getattr(grand_ino);
        }
        let child_path = join_child(&parent_path, name)?;
        if self.file_exists(&child_path) || self.dir_exists(&child_path) {
            let ino = self.ensure_inode(&child_path);
            self.getattr(ino)
        } else {
            Err(libc::ENOENT)
        }
    }

    /// Fetch attributes for `ino` without hydrating unmodified base blobs.
    pub fn getattr(&self, ino: u64) -> PosixResult<VfsAttr> {
        let path = self.ino_to_path.get(&ino).ok_or(libc::ENOENT)?;
        if path.is_empty() || self.dir_exists(path) {
            return Ok(VfsAttr {
                ino,
                kind: VfsFileType::Directory,
                size: BLOCK_SIZE as u64,
                perm: 0o755,
                nlink: 2,
                uid: self.uid,
                gid: self.gid,
                mtime: self.mtime,
            });
        }
        self.file_attr_for_path(ino, path)
    }

    /// List `.`, `..`, and sorted immediate children of directory `ino`.
    pub fn readdir(&mut self, ino: u64) -> PosixResult<Vec<VfsDirEntry>> {
        let dir_path = self.require_dir_path(ino)?;
        let parent_ino = self.parent_ino_for_path(&dir_path);

        let children = self.collect_immediate_children(&dir_path);
        let mut entries = Vec::with_capacity(children.len() + 2);
        entries.push(VfsDirEntry {
            ino,
            name: ".".to_string(),
            kind: VfsFileType::Directory,
        });
        entries.push(VfsDirEntry {
            ino: parent_ino,
            name: "..".to_string(),
            kind: VfsFileType::Directory,
        });

        for (name, kind) in children {
            let child_path = if dir_path.is_empty() {
                name.clone()
            } else {
                format!("{dir_path}/{name}")
            };
            let child_ino = self.ensure_inode(&child_path);
            entries.push(VfsDirEntry {
                ino: child_ino,
                name,
                kind,
            });
        }

        Ok(entries)
    }

    /// Open a regular file inode, optionally truncating it to 0 bytes when `O_TRUNC` is set.
    pub fn open(&mut self, ino: u64, flags: i32) -> PosixResult<u64> {
        let path = self.require_file_path(ino)?;
        if (flags & libc::O_TRUNC) != 0 {
            let mode = self.file_mode_for_path(&path)?;
            self.workspace
                .write_file(&path, &[], mode)
                .map_err(gitx_err_to_errno)?;
            self.mtime = SystemTime::now();
        }
        Ok(self.alloc_fh())
    }

    /// Demand-page and read up to `size` bytes at `offset` from file `ino`.
    pub fn read(&self, ino: u64, offset: u64, size: u32) -> PosixResult<Vec<u8>> {
        let path = self.require_file_path(ino)?;
        let data = self.workspace.read_file(&path).map_err(gitx_err_to_errno)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= data.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(size as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    /// Read the target path of a symbolic link inode.
    pub fn readlink(&self, ino: u64) -> PosixResult<Vec<u8>> {
        let path = self.require_file_path(ino)?;
        let mode = self.file_mode_for_path(&path)?;
        if mode != FileMode::Symlink {
            return Err(libc::EINVAL);
        }
        self.workspace.read_file(&path).map_err(gitx_err_to_errno)
    }

    /// Create (or open if already present and not `O_EXCL`) a file in directory `parent`.
    pub fn create(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
        flags: i32,
    ) -> PosixResult<(VfsAttr, u64)> {
        let parent_path = self.require_dir_path(parent)?;
        let child_path = join_child(&parent_path, name)?;

        if self.dir_exists(&child_path) {
            return Err(libc::EISDIR);
        }

        let file_mode = mode_bits_to_file_mode(mode);
        let existed = self.file_exists(&child_path);
        if existed {
            if (flags & libc::O_EXCL) != 0 {
                return Err(libc::EEXIST);
            }
            if (flags & libc::O_TRUNC) != 0 {
                let existing_mode = self.file_mode_for_path(&child_path)?;
                self.workspace
                    .write_file(&child_path, &[], existing_mode)
                    .map_err(gitx_err_to_errno)?;
                self.mtime = SystemTime::now();
            }
        } else {
            self.workspace
                .write_file(&child_path, &[], file_mode)
                .map_err(gitx_err_to_errno)?;
            self.mtime = SystemTime::now();
        }

        let ino = self.ensure_inode(&child_path);
        let attr = self.getattr(ino)?;
        let fh = self.alloc_fh();
        Ok((attr, fh))
    }

    /// Write `data` at `offset` into file `ino` using Copy-on-Write into the sparse overlay.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> PosixResult<u32> {
        let path = self.require_file_path(ino)?;
        let mode = self.file_mode_for_path(&path)?;
        let start = usize::try_from(offset).map_err(|_| libc::EFBIG)?;
        let end = start.checked_add(data.len()).ok_or(libc::EFBIG)?;

        let current_size = self.file_attr_for_path(ino, &path)?.size;
        let mut buf = if start == 0 && current_size == 0 {
            Vec::with_capacity(data.len())
        } else {
            self.workspace
                .read_file(&path)
                .map_err(gitx_err_to_errno)?
        };

        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);

        self.workspace
            .write_file(&path, &buf, mode)
            .map_err(gitx_err_to_errno)?;
        self.mtime = SystemTime::now();

        u32::try_from(data.len()).map_err(|_| libc::EOVERFLOW)
    }

    /// Update file mode and/or size (including truncate/extend) on `ino`.
    pub fn setattr(
        &mut self,
        ino: u64,
        mode: Option<u32>,
        size: Option<u64>,
    ) -> PosixResult<VfsAttr> {
        let path = self.ino_to_path.get(&ino).ok_or(libc::ENOENT)?.clone();
        if path.is_empty() || self.dir_exists(&path) {
            if size.is_some() {
                return Err(libc::EISDIR);
            }
            self.mtime = SystemTime::now();
            return self.getattr(ino);
        }

        if !self.file_exists(&path) {
            return Err(libc::ENOENT);
        }

        let old_mode = self.file_mode_for_path(&path)?;
        let new_mode = match mode {
            Some(bits) if old_mode != FileMode::Symlink => mode_bits_to_file_mode(bits),
            _ => old_mode,
        };

        if let Some(new_size) = size {
            let target_len = usize::try_from(new_size).map_err(|_| libc::EFBIG)?;
            if target_len == 0 {
                // Truncating to 0 never requires hydrating the base blob from ObjectStore.
                self.workspace
                    .write_file(&path, &[], new_mode)
                    .map_err(gitx_err_to_errno)?;
            } else {
                let mut bytes = self
                    .workspace
                    .read_file(&path)
                    .map_err(gitx_err_to_errno)?;
                bytes.resize(target_len, 0);
                self.workspace
                    .write_file(&path, &bytes, new_mode)
                    .map_err(gitx_err_to_errno)?;
            }
            self.mtime = SystemTime::now();
        } else if new_mode != old_mode {
            let bytes = self
                .workspace
                .read_file(&path)
                .map_err(gitx_err_to_errno)?;
            self.workspace
                .write_file(&path, &bytes, new_mode)
                .map_err(gitx_err_to_errno)?;
            self.mtime = SystemTime::now();
        }

        self.getattr(ino)
    }

    /// Unlink (delete) a file in directory `parent`, recording a tombstone if it existed in base.
    pub fn unlink(&mut self, parent: u64, name: &str) -> PosixResult<()> {
        let parent_path = self.require_dir_path(parent)?;
        let child_path = join_child(&parent_path, name)?;

        if self.dir_exists(&child_path) {
            return Err(libc::EISDIR);
        }
        if !self.file_exists(&child_path) {
            return Err(libc::ENOENT);
        }

        // Keep non-root parent directory alive in POSIX view even if its last file is unlinked.
        if !parent_path.is_empty() {
            self.explicit_dirs.insert(parent_path);
        }

        self.workspace
            .remove_file(&child_path)
            .map_err(gitx_err_to_errno)?;
        self.remove_inode(&child_path);
        self.mtime = SystemTime::now();
        Ok(())
    }

    /// Create an empty virtual directory `name` under `parent`.
    pub fn mkdir(&mut self, parent: u64, name: &str) -> PosixResult<VfsAttr> {
        let parent_path = self.require_dir_path(parent)?;
        let child_path = join_child(&parent_path, name)?;

        if self.file_exists(&child_path) || self.dir_exists(&child_path) {
            return Err(libc::EEXIST);
        }

        self.explicit_dirs.insert(child_path.clone());
        let ino = self.ensure_inode(&child_path);
        self.mtime = SystemTime::now();
        self.getattr(ino)
    }

    /// Remove an empty virtual directory `name` under `parent`.
    pub fn rmdir(&mut self, parent: u64, name: &str) -> PosixResult<()> {
        let parent_path = self.require_dir_path(parent)?;
        let child_path = join_child(&parent_path, name)?;

        if self.file_exists(&child_path) {
            return Err(libc::ENOTDIR);
        }
        if !self.dir_exists(&child_path) {
            return Err(libc::ENOENT);
        }
        if self.has_any_children(&child_path) {
            return Err(libc::ENOTEMPTY);
        }

        if !parent_path.is_empty() {
            self.explicit_dirs.insert(parent_path);
        }
        self.explicit_dirs.remove(&child_path);
        self.remove_inode(&child_path);
        self.mtime = SystemTime::now();
        Ok(())
    }

    /// Create a symbolic link `link_name` under `parent` pointing to `target`.
    pub fn symlink(&mut self, parent: u64, link_name: &str, target: &str) -> PosixResult<VfsAttr> {
        let parent_path = self.require_dir_path(parent)?;
        let child_path = join_child(&parent_path, link_name)?;

        if self.file_exists(&child_path) || self.dir_exists(&child_path) {
            return Err(libc::EEXIST);
        }

        self.workspace
            .write_file(&child_path, target.as_bytes(), FileMode::Symlink)
            .map_err(gitx_err_to_errno)?;
        let ino = self.ensure_inode(&child_path);
        self.mtime = SystemTime::now();
        self.getattr(ino)
    }

    /// Rename a file or directory from `(parent, name)` to `(newparent, newname)`.
    pub fn rename(
        &mut self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
        flags: u32,
    ) -> PosixResult<()> {
        // Only standard rename (0) and RENAME_NOREPLACE (1) are supported.
        if (flags & !RENAME_NOREPLACE) != 0 {
            return Err(libc::EINVAL);
        }

        let old_parent = self.require_dir_path(parent)?;
        let new_parent = self.require_dir_path(newparent)?;
        let old_path = join_child(&old_parent, name)?;
        let new_path = join_child(&new_parent, newname)?;

        let src_is_file = self.file_exists(&old_path);
        let src_is_dir = !src_is_file && self.dir_exists(&old_path);
        if !src_is_file && !src_is_dir {
            return Err(libc::ENOENT);
        }

        if old_path == new_path {
            return Ok(());
        }

        let dst_is_file = self.file_exists(&new_path);
        let dst_is_dir = !dst_is_file && self.dir_exists(&new_path);

        if (flags & RENAME_NOREPLACE) != 0 && (dst_is_file || dst_is_dir) {
            return Err(libc::EEXIST);
        }

        if !old_parent.is_empty() {
            self.explicit_dirs.insert(old_parent);
        }

        if src_is_file {
            if dst_is_dir {
                return Err(libc::EISDIR);
            }
            let mode = self.file_mode_for_path(&old_path)?;
            let data = self
                .workspace
                .read_file(&old_path)
                .map_err(gitx_err_to_errno)?;

            if dst_is_file {
                self.remove_inode(&new_path);
            }

            self.workspace
                .write_file(&new_path, &data, mode)
                .map_err(gitx_err_to_errno)?;
            self.workspace
                .remove_file(&old_path)
                .map_err(gitx_err_to_errno)?;

            self.rebind_inode(&old_path, &new_path);
            self.mtime = SystemTime::now();
            return Ok(());
        }

        // Source is a directory.
        let old_prefix = format!("{old_path}/");
        if new_path.starts_with(&old_prefix) {
            return Err(libc::EINVAL);
        }
        if dst_is_file {
            return Err(libc::ENOTDIR);
        }
        if dst_is_dir {
            if self.has_any_children(&new_path) {
                return Err(libc::ENOTEMPTY);
            }
            self.explicit_dirs.remove(&new_path);
            self.remove_inode(&new_path);
        }

        // Move all virtual files under `old_path/`.
        let files_to_move = self
            .workspace
            .list_dir(&old_path)
            .map_err(gitx_err_to_errno)?;
        for src_file in &files_to_move {
            if let Some(rel) = src_file.strip_prefix(&old_prefix) {
                let dst_file = format!("{new_path}/{rel}");
                let mode = self.file_mode_for_path(src_file)?;
                let data = self
                    .workspace
                    .read_file(src_file)
                    .map_err(gitx_err_to_errno)?;
                self.workspace
                    .write_file(&dst_file, &data, mode)
                    .map_err(gitx_err_to_errno)?;
                self.workspace
                    .remove_file(src_file)
                    .map_err(gitx_err_to_errno)?;
            }
        }

        // Move explicit directories at or under `old_path`.
        let dirs_to_move: Vec<String> = self
            .explicit_dirs
            .iter()
            .filter(|d| d.as_str() == old_path || d.starts_with(&old_prefix))
            .cloned()
            .collect();
        for d in dirs_to_move {
            self.explicit_dirs.remove(&d);
            let mapped = if d == old_path {
                new_path.clone()
            } else {
                format!("{new_path}/{}", &d[old_prefix.len()..])
            };
            self.explicit_dirs.insert(mapped);
        }
        if files_to_move.is_empty() {
            self.explicit_dirs.insert(new_path.clone());
        }

        // Rebind allocated inodes for `old_path` and any tracked descendants.
        let tracked_paths: Vec<(String, u64)> = self
            .path_to_ino
            .iter()
            .filter(|(p, _)| p.as_str() == old_path || p.starts_with(&old_prefix))
            .map(|(p, &i)| (p.clone(), i))
            .collect();
        for (p, ino) in tracked_paths {
            self.path_to_ino.remove(&p);
            let mapped = if p == old_path {
                new_path.clone()
            } else {
                format!("{new_path}/{}", &p[old_prefix.len()..])
            };
            self.path_to_ino.insert(mapped.clone(), ino);
            self.ino_to_path.insert(ino, mapped);
        }

        self.mtime = SystemTime::now();
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn alloc_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        fh
    }

    fn ensure_inode(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let owned = path.to_string();
        self.path_to_ino.insert(owned.clone(), ino);
        self.ino_to_path.insert(ino, owned);
        ino
    }

    fn remove_inode(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
        }
    }

    fn rebind_inode(&mut self, old_path: &str, new_path: &str) {
        if let Some(ino) = self.path_to_ino.remove(old_path) {
            self.path_to_ino.insert(new_path.to_string(), ino);
            self.ino_to_path.insert(ino, new_path.to_string());
        } else {
            let _ = self.ensure_inode(new_path);
        }
    }

    fn parent_ino_for_path(&mut self, path: &str) -> u64 {
        if path.is_empty() {
            return ROOT_INO;
        }
        match path.rsplit_once('/') {
            Some((parent, _)) => self.ensure_inode(parent),
            None => ROOT_INO,
        }
    }

    fn require_dir_path(&self, ino: u64) -> PosixResult<String> {
        let path = self.ino_to_path.get(&ino).ok_or(libc::ENOENT)?;
        if path.is_empty() || self.dir_exists(path) {
            Ok(path.clone())
        } else if self.file_exists(path) {
            Err(libc::ENOTDIR)
        } else {
            Err(libc::ENOENT)
        }
    }

    fn require_file_path(&self, ino: u64) -> PosixResult<String> {
        let path = self.ino_to_path.get(&ino).ok_or(libc::ENOENT)?;
        if path.is_empty() || self.dir_exists(path) {
            Err(libc::EISDIR)
        } else if self.file_exists(path) {
            Ok(path.clone())
        } else {
            Err(libc::ENOENT)
        }
    }

    fn file_exists(&self, norm: &str) -> bool {
        if norm.is_empty() || self.workspace.tombstones().contains(norm) {
            return false;
        }
        self.workspace.dirty_files().contains_key(norm)
            || self.workspace.base_tree().entries.contains_key(norm)
    }

    fn dir_exists(&self, norm: &str) -> bool {
        if norm.is_empty() {
            return true;
        }
        if self.explicit_dirs.contains(norm) {
            return true;
        }
        self.has_any_children(norm)
    }

    fn has_any_children(&self, dir_path: &str) -> bool {
        let prefix = if dir_path.is_empty() {
            String::new()
        } else {
            format!("{dir_path}/")
        };

        for key in self
            .workspace
            .base_tree()
            .entries
            .range(prefix.clone()..)
            .map(|(k, _)| k)
        {
            if !prefix.is_empty() && !key.starts_with(&prefix) {
                break;
            }
            if !self.workspace.tombstones().contains(key) {
                return true;
            }
        }

        if let Some((key, _)) = self.workspace.dirty_files().range(prefix.clone()..).next()
            && (prefix.is_empty() || key.starts_with(&prefix))
        {
            return true;
        }

        for dir in self.explicit_dirs.range(prefix.clone()..) {
            if !prefix.is_empty() && !dir.starts_with(&prefix) {
                break;
            }
            if dir.as_str() != dir_path {
                return true;
            }
        }

        false
    }

    /// Collect sorted immediate children of `dir_path` using B-tree range skipping
    /// so directories with many nested files skip each subdirectory in O(log N).
    fn collect_immediate_children(&self, dir_path: &str) -> BTreeMap<String, VfsFileType> {
        let prefix = if dir_path.is_empty() {
            String::new()
        } else {
            format!("{dir_path}/")
        };

        let mut children: BTreeMap<String, VfsFileType> = BTreeMap::new();

        // 1. Base tree entries (skipping tombstones, jumping past discovered subdirectories).
        let mut cursor = prefix.clone();
        loop {
            let mut next_jump: Option<String> = None;
            let mut exhausted = true;
            for (key, entry) in self.workspace.base_tree().entries.range(cursor.clone()..) {
                if !prefix.is_empty() && !key.starts_with(&prefix) {
                    break;
                }
                if self.workspace.tombstones().contains(key) {
                    continue;
                }
                let rest = &key[prefix.len()..];
                if let Some((sub, _)) = rest.split_once('/') {
                    children.insert(sub.to_string(), VfsFileType::Directory);
                    // `'/'` (0x2F) + 1 == `'0'` (0x30): jump straight past all entries under `sub/`.
                    next_jump = Some(format!("{prefix}{sub}0"));
                    exhausted = false;
                    break;
                } else {
                    let kind = match entry {
                        EntryKind::File {
                            mode: FileMode::Symlink,
                            ..
                        }
                        | EntryKind::Conflict {
                            mode: FileMode::Symlink,
                            ..
                        }
                        | EntryKind::EncryptedSecret {
                            mode: FileMode::Symlink,
                            ..
                        } => VfsFileType::Symlink,
                        _ => VfsFileType::RegularFile,
                    };
                    children.insert(rest.to_string(), kind);
                }
            }
            if exhausted {
                break;
            }
            if let Some(jump) = next_jump {
                cursor = jump;
            } else {
                break;
            }
        }

        // 2. Dirty overlay files.
        let mut cursor = prefix.clone();
        loop {
            let mut next_jump: Option<String> = None;
            let mut exhausted = true;
            for (key, &mode) in self.workspace.dirty_files().range(cursor.clone()..) {
                if !prefix.is_empty() && !key.starts_with(&prefix) {
                    break;
                }
                let rest = &key[prefix.len()..];
                if let Some((sub, _)) = rest.split_once('/') {
                    children.insert(sub.to_string(), VfsFileType::Directory);
                    next_jump = Some(format!("{prefix}{sub}0"));
                    exhausted = false;
                    break;
                } else {
                    let kind = if mode == FileMode::Symlink {
                        VfsFileType::Symlink
                    } else {
                        VfsFileType::RegularFile
                    };
                    children.insert(rest.to_string(), kind);
                }
            }
            if exhausted {
                break;
            }
            if let Some(jump) = next_jump {
                cursor = jump;
            } else {
                break;
            }
        }

        // 3. Explicit directories (e.g., empty directories created by mkdir).
        for dir in self.explicit_dirs.range(prefix.clone()..) {
            if !prefix.is_empty() && !dir.starts_with(&prefix) {
                break;
            }
            if dir.as_str() == dir_path {
                continue;
            }
            let rest = &dir[prefix.len()..];
            let first = rest.split('/').next().unwrap_or(rest);
            if !first.is_empty() {
                children.insert(first.to_string(), VfsFileType::Directory);
            }
        }

        children
    }

    fn file_mode_for_path(&self, norm: &str) -> PosixResult<FileMode> {
        if self.workspace.tombstones().contains(norm) {
            return Err(libc::ENOENT);
        }
        if let Some(&mode) = self.workspace.dirty_files().get(norm) {
            return Ok(mode);
        }
        match self.workspace.base_tree().entries.get(norm) {
            Some(EntryKind::File { mode, .. }) | Some(EntryKind::Conflict { mode, .. }) => {
                Ok(*mode)
            }
            Some(EntryKind::EncryptedSecret { .. }) => Err(libc::EACCES),
            None => Err(libc::ENOENT),
        }
    }

    fn file_attr_for_path(&self, ino: u64, norm: &str) -> PosixResult<VfsAttr> {
        if self.workspace.tombstones().contains(norm) {
            return Err(libc::ENOENT);
        }

        if let Some(&mode) = self.workspace.dirty_files().get(norm) {
            let full = self.workspace.overlay_root().join(norm);
            let meta = fs::symlink_metadata(&full).map_err(|_| libc::ENOENT)?;
            let size = if meta.file_type().is_symlink() {
                fs::read_link(&full)
                    .map(|p| p.to_string_lossy().len() as u64)
                    .unwrap_or(meta.len())
            } else {
                meta.len()
            };
            let mtime = meta.modified().unwrap_or(self.mtime);
            let (kind, perm) = file_mode_to_kind_perm(mode);
            return Ok(VfsAttr {
                ino,
                kind,
                size,
                perm,
                nlink: 1,
                uid: self.uid,
                gid: self.gid,
                mtime,
            });
        }

        match self.workspace.base_tree().entries.get(norm) {
            Some(EntryKind::File { mode, size, .. }) => {
                let (kind, perm) = file_mode_to_kind_perm(*mode);
                Ok(VfsAttr {
                    ino,
                    kind,
                    size: *size,
                    perm,
                    nlink: 1,
                    uid: self.uid,
                    gid: self.gid,
                    mtime: self.mtime,
                })
            }
            Some(EntryKind::Conflict { mode, .. }) => {
                let size = self
                    .workspace
                    .read_file(norm)
                    .map(|b| b.len() as u64)
                    .map_err(gitx_err_to_errno)?;
                let (kind, perm) = file_mode_to_kind_perm(*mode);
                Ok(VfsAttr {
                    ino,
                    kind,
                    size,
                    perm,
                    nlink: 1,
                    uid: self.uid,
                    gid: self.gid,
                    mtime: self.mtime,
                })
            }
            Some(EntryKind::EncryptedSecret { .. }) => Err(libc::EACCES),
            None => Err(libc::ENOENT),
        }
    }
}

fn join_child(parent_path: &str, name: &str) -> PosixResult<String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(libc::EINVAL);
    }
    let raw = if parent_path.is_empty() {
        name.to_string()
    } else {
        format!("{parent_path}/{name}")
    };
    normalize_rel_path(&raw).map_err(|_| libc::EINVAL)
}

fn file_mode_to_kind_perm(mode: FileMode) -> (VfsFileType, u16) {
    match mode {
        FileMode::Regular => (VfsFileType::RegularFile, 0o644),
        FileMode::Executable => (VfsFileType::RegularFile, 0o755),
        FileMode::Symlink => (VfsFileType::Symlink, 0o777),
    }
}

fn mode_bits_to_file_mode(mode: u32) -> FileMode {
    if (mode & 0o111) != 0 {
        FileMode::Executable
    } else {
        FileMode::Regular
    }
}

fn gitx_err_to_errno(err: GitxError) -> i32 {
    match err {
        GitxError::NotFound(_) => libc::ENOENT,
        GitxError::AccessDenied { .. } => libc::EACCES,
        GitxError::Io(io_err) => io_err.raw_os_error().unwrap_or(libc::EIO),
        _ => libc::EIO,
    }
}

#[cfg(unix)]
fn current_uid_gid() -> (u32, u32) {
    // SAFETY: `getuid` and `getgid` are always safe POSIX syscalls with no preconditions.
    unsafe { (libc::getuid(), libc::getgid()) }
}

#[cfg(not(unix))]
fn current_uid_gid() -> (u32, u32) {
    (0, 0)
}

// =============================================================================
// Linux FUSE3 Filesystem + Background Mount Handle (`fuser`)
// =============================================================================

/// Linux FUSE3 [`fuser::Filesystem`] adapter backed by a demand-paged [`LazyWorkspace`].
#[cfg(all(target_os = "linux", feature = "fuse"))]
pub struct GitxFuseFs {
    core: Arc<Mutex<FuseCore>>,
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
impl GitxFuseFs {
    /// Construct a new [`GitxFuseFs`] owning its own shared [`FuseCore`].
    pub fn new(workspace: LazyWorkspace, store: Arc<dyn ObjectStore>) -> Self {
        Self {
            core: Arc::new(Mutex::new(FuseCore::new(workspace, store))),
        }
    }

    /// Construct a [`GitxFuseFs`] sharing an existing `Arc<Mutex<FuseCore>>`.
    pub fn from_shared(core: Arc<Mutex<FuseCore>>) -> Self {
        Self { core }
    }

    /// Access the underlying shared [`FuseCore`].
    pub fn core(&self) -> &Arc<Mutex<FuseCore>> {
        &self.core
    }
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
fn os_str_to_utf8(name: &OsStr) -> PosixResult<&str> {
    name.to_str().ok_or(libc::EINVAL)
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
impl Filesystem for GitxFuseFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Ok(name_str) = os_str_to_utf8(name) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.lookup(parent, name_str) {
            Ok(attr) => reply.entry(&TTL, &attr.to_fuse_attr(), 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.getattr(ino) {
            Ok(attr) => reply.attr(&TTL, &attr.to_fuse_attr()),
            Err(errno) => reply.error(errno),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.setattr(ino, mode, size) {
            Ok(attr) => reply.attr(&TTL, &attr.to_fuse_attr()),
            Err(errno) => reply.error(errno),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.readlink(ino) {
            Ok(target) => reply.data(&target),
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Ok(name_str) = os_str_to_utf8(name) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.mkdir(parent, name_str) {
            Ok(attr) => reply.entry(&TTL, &attr.to_fuse_attr(), 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Ok(name_str) = os_str_to_utf8(name) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.unlink(parent, name_str) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Ok(name_str) = os_str_to_utf8(name) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.rmdir(parent, name_str) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let (Ok(name_str), Some(target_str)) = (os_str_to_utf8(link_name), target.to_str()) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.symlink(parent, name_str, target_str) {
            Ok(attr) => reply.entry(&TTL, &attr.to_fuse_attr(), 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Ok(old_str), Ok(new_str)) = (os_str_to_utf8(name), os_str_to_utf8(newname)) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.rename(parent, old_str, newparent, new_str, flags) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.open(ino, flags) {
            Ok(fh) => reply.opened(fh, 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.read(ino, offset as u64, size) {
            Ok(data) => reply.data(&data),
            Err(errno) => reply.error(errno),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.write(ino, offset as u64, data) {
            Ok(written) => reply.written(written),
            Err(errno) => reply.error(errno),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.readdir(ino) {
            Ok(entries) => {
                for (idx, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    if reply.add(entry.ino, (idx + 1) as i64, entry.kind.into(), &entry.name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        let files = core.stats().total_virtual_files as u64;
        reply.statfs(1_000_000, 500_000, 500_000, files, 1_000_000, BLOCK_SIZE, 255, BLOCK_SIZE);
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, _mask: i32, reply: ReplyEmpty) {
        let core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.getattr(ino) {
            Ok(_) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Ok(name_str) = os_str_to_utf8(name) else {
            reply.error(libc::EINVAL);
            return;
        };
        let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
        match core.create(parent, name_str, mode, flags) {
            Ok((attr, fh)) => reply.created(&TTL, &attr.to_fuse_attr(), 0, fh, 0),
            Err(errno) => reply.error(errno),
        }
    }
}

/// Handle to a live background Linux FUSE3 mount spawned via [`fuser::spawn_mount2`].
///
/// Unmounts automatically when dropped, or explicitly via [`FuseMountHandle::unmount`].
#[cfg(all(target_os = "linux", feature = "fuse"))]
pub struct FuseMountHandle {
    mountpoint: PathBuf,
    core: Arc<Mutex<FuseCore>>,
    session: Option<BackgroundSession>,
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
impl FuseMountHandle {
    /// Mount `workspace` onto `mountpoint` in a background FUSE3 session.
    pub fn mount_background(
        mountpoint: impl AsRef<Path>,
        workspace: LazyWorkspace,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self> {
        let mountpoint = mountpoint.as_ref().to_path_buf();
        fs::create_dir_all(&mountpoint)?;

        let core = Arc::new(Mutex::new(FuseCore::new(workspace, store)));
        let fs_impl = GitxFuseFs::from_shared(Arc::clone(&core));
        let options = [
            MountOption::FSName("gitx-vfs".to_string()),
            MountOption::RW,
            MountOption::NoDev,
            MountOption::NoSuid,
        ];

        let session = fuser::spawn_mount2(fs_impl, &mountpoint, &options)?;
        Ok(Self {
            mountpoint,
            core,
            session: Some(session),
        })
    }

    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    pub fn core(&self) -> &Arc<Mutex<FuseCore>> {
        &self.core
    }

    pub fn stats(&self) -> LazyStats {
        self.core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stats()
    }

    pub fn snapshot(&self, domain: DomainId) -> Result<DomainTree> {
        self.core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot(domain)
    }

    /// Returns `true` while the background FUSE3 worker thread is still running.
    pub fn is_alive(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| !s.guard.is_finished())
    }

    /// Explicitly unmount the FUSE3 mountpoint and join the background worker thread.
    pub fn unmount(mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            session.join();
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
        }
    }
}
