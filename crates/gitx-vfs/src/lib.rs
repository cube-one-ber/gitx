pub mod backend;
#[cfg(feature = "cow")]
pub mod cow;
#[cfg(feature = "cow")]
pub mod fleet;
#[cfg(feature = "cow")]
pub mod fuse_mount;
#[cfg(feature = "cow")]
pub mod lazy;
pub mod manager;
pub mod memory;
#[cfg(feature = "cow")]
pub mod nfs_mount;

pub use backend::{WorkspaceBackend, normalize_rel_path};
#[cfg(feature = "cow")]
pub use cow::{CowWorkspace, DEFAULT_IGNORES};
#[cfg(feature = "cow")]
pub use fleet::{
    EncryptedFleetBundle, FLEET_EXCLUDED_DIRS, FleetOverlayBundle, FleetWorkspaceMetadata,
    OverlayFile, apply_encrypted_overlay, apply_overlay, export_encrypted_overlay, export_overlay,
    export_overlay_with_metadata,
};
#[cfg(all(target_os = "linux", feature = "cow", feature = "fuse"))]
pub use fuse_mount::{FuseMountHandle, GitxFuseFs};
#[cfg(feature = "cow")]
pub use fuse_mount::{FuseCore, PosixResult, ROOT_INO, VfsAttr, VfsDirEntry, VfsFileType};
pub use gitx_core::oplog::WorkspaceBackendKind;
#[cfg(feature = "cow")]
pub use lazy::{LazyStats, LazyWorkspace};
pub use manager::{WorkspaceChanges, WorkspaceManager, detect_changes};
pub use memory::MemVfs;
#[cfg(feature = "cow")]
pub use nfs_mount::{
    LoopbackVfsClient, LoopbackVfsServer, NfsAttr, NfsRpcRequest, NfsRpcResponse,
};
