pub mod backend;
pub mod cow;
pub mod fleet;
pub mod manager;
pub mod memory;

pub use backend::{WorkspaceBackend, normalize_rel_path};
pub use cow::{CowWorkspace, DEFAULT_IGNORES};
pub use fleet::{
    FLEET_EXCLUDED_DIRS, FleetOverlayBundle, FleetWorkspaceMetadata, OverlayFile, apply_overlay,
    export_overlay, export_overlay_with_metadata,
};
pub use gitx_core::oplog::WorkspaceBackendKind;
pub use manager::{WorkspaceChanges, WorkspaceManager, detect_changes};
pub use memory::MemVfs;
