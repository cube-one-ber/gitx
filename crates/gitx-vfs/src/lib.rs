pub mod backend;
#[cfg(feature = "cow")]
pub mod cow;
#[cfg(feature = "cow")]
pub mod fleet;
#[cfg(feature = "cow")]
pub mod lazy;
pub mod manager;
pub mod memory;

pub use backend::{WorkspaceBackend, normalize_rel_path};
#[cfg(feature = "cow")]
pub use cow::{CowWorkspace, DEFAULT_IGNORES};
#[cfg(feature = "cow")]
pub use fleet::{
    EncryptedFleetBundle, FLEET_EXCLUDED_DIRS, FleetOverlayBundle, FleetWorkspaceMetadata,
    OverlayFile, apply_encrypted_overlay, apply_overlay, export_encrypted_overlay, export_overlay,
    export_overlay_with_metadata,
};
pub use gitx_core::oplog::WorkspaceBackendKind;
#[cfg(feature = "cow")]
pub use lazy::{LazyStats, LazyWorkspace};
pub use manager::{WorkspaceChanges, WorkspaceManager, detect_changes};
pub use memory::MemVfs;
