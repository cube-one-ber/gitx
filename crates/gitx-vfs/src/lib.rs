pub mod backend;
pub mod cow;
pub mod fleet;
pub mod fuse_mount;
pub mod lazy;
pub mod manager;
pub mod memory;
pub mod nfs_mount;

pub use backend::{WorkspaceBackend, normalize_rel_path};
pub use cow::{CowWorkspace, DEFAULT_IGNORES};
pub use fleet::{
    EncryptedFleetBundle, FLEET_EXCLUDED_DIRS, FleetOverlayBundle, FleetWorkspaceMetadata,
    OverlayFile, apply_encrypted_overlay, apply_overlay, export_encrypted_overlay, export_overlay,
    export_overlay_with_metadata,
};
#[cfg(all(target_os = "linux", feature = "fuse"))]
pub use fuse_mount::{FuseMountHandle, GitxFuseFs};
pub use fuse_mount::{FuseCore, PosixResult, ROOT_INO, VfsAttr, VfsDirEntry, VfsFileType};
pub use gitx_core::oplog::WorkspaceBackendKind;
pub use lazy::{LazyStats, LazyWorkspace};
pub use manager::{WorkspaceChanges, WorkspaceManager, detect_changes};
pub use memory::MemVfs;
pub use nfs_mount::{
    LoopbackVfsClient, LoopbackVfsServer, NfsAttr, NfsRpcRequest, NfsRpcResponse,
};
