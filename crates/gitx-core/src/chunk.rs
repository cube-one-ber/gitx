use crate::hash::ObjectHash;
use fastcdc::v2020::FastCDC;
use serde::{Deserialize, Serialize};

/// Default FastCDC chunking thresholds (64 KiB avg, handles both source and huge binaries natively).
pub const MIN_CHUNK_SIZE: u32 = 16 * 1024;
pub const AVG_CHUNK_SIZE: u32 = 64 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 256 * 1024;
pub const INLINE_THRESHOLD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub hash: ObjectHash,
    pub length: u64,
}

/// Content-defined chunked blob manifest (replaces both Git loose blobs and Git LFS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedBlob {
    pub total_size: u64,
    pub content_hash: ObjectHash,
    pub chunks: Vec<ChunkMeta>,
}

impl ChunkedBlob {
    pub fn manifest_hash(&self) -> ObjectHash {
        let bytes = bincode::serialize(self).expect("ChunkedBlob serialization cannot fail");
        ObjectHash::of_typed("gitx:blob:v1", &bytes)
    }
}

/// Split arbitrary bytes into FastCDC chunks and return `(ChunkedBlob, Vec<(ObjectHash, Vec<u8>)>)`.
pub fn chunk_bytes(data: &[u8]) -> (ChunkedBlob, Vec<(ObjectHash, Vec<u8>)>) {
    let content_hash = ObjectHash::of_typed("gitx:raw:v1", data);
    if data.len() <= INLINE_THRESHOLD {
        let h = ObjectHash::of_typed("gitx:chunk:v1", data);
        let blob = ChunkedBlob {
            total_size: data.len() as u64,
            content_hash,
            chunks: vec![ChunkMeta {
                hash: h,
                length: data.len() as u64,
            }],
        };
        return (blob, vec![(h, data.to_vec())]);
    }

    let chunker = FastCDC::new(data, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let mut metas = Vec::new();
    let mut payloads = Vec::new();
    for chunk in chunker {
        let slice = &data[chunk.offset..chunk.offset + chunk.length];
        let h = ObjectHash::of_typed("gitx:chunk:v1", slice);
        metas.push(ChunkMeta {
            hash: h,
            length: chunk.length as u64,
        });
        payloads.push((h, slice.to_vec()));
    }

    let blob = ChunkedBlob {
        total_size: data.len() as u64,
        content_hash,
        chunks: metas,
    };
    (blob, payloads)
}
