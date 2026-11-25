#[cfg(feature = "local")]
pub mod local;
pub mod memory;
#[cfg(feature = "local")]
pub mod metadata;
#[cfg(feature = "distributed")]
pub mod postgres;
pub mod store;
#[cfg(feature = "distributed")]
pub mod tiered;

#[cfg(feature = "local")]
pub use local::LocalStore;
pub use memory::MemoryStore;
#[cfg(feature = "local")]
pub use metadata::{
    MetadataBackend, Migration, POSTGRES_MIGRATIONS, PostgresConfig, PostgresSslMode,
    SQLITE_MIGRATIONS, SqlDialect, SqlMetadataBackend, pg_queries, postgres_schema_ddl,
    sqlite_schema_ddl,
};
pub use store::{LandRecord, ObjectStore};
#[cfg(feature = "distributed")]
pub use tiered::{
    BlobBackendConfig, BoundedLruCache, CacheConfig, CacheMetricsSnapshot, GcsConfig, S3Config,
    TieredObjectStore,
};
