#[cfg(feature = "local")]
pub mod local;
pub mod memory;
pub mod store;

#[cfg(feature = "local")]
pub use local::LocalStore;
pub use memory::MemoryStore;
pub use store::{LandRecord, ObjectStore};
