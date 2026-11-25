//! Git Smart HTTP pkt-line framing and `git-upload-pack --stateless-rpc` helpers.

use gitx_core::{GitxError, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Content-Type header for `GET /info/refs?service=git-upload-pack`.
pub const UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE: &str =
    "application/x-git-upload-pack-advertisement";

/// Content-Type header for `POST /git-upload-pack`.
pub const UPLOAD_PACK_RESULT_CONTENT_TYPE: &str = "application/x-git-upload-pack-result";

/// Content-Type header for `GET /info/refs?service=git-receive-pack`.
pub const RECEIVE_PACK_ADVERTISEMENT_CONTENT_TYPE: &str =
    "application/x-git-receive-pack-advertisement";

/// Content-Type header for `POST /git-receive-pack`.
pub const RECEIVE_PACK_RESULT_CONTENT_TYPE: &str = "application/x-git-receive-pack-result";

/// Git pkt-line flush packet (`0000`).
pub const FLUSH_PKT: &[u8] = b"0000";

/// Git pkt-line delimiter packet (`0001`, used in protocol v2).
pub const DELIM_PKT: &[u8] = b"0001";

/// Maximum payload length for a single Git pkt-line (`65520 - 4`).
const MAX_PKT_PAYLOAD: usize = 65516;

/// Decoded Git pkt-line frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine {
    Flush,
    Delim,
    ResponseEnd,
    Data(Vec<u8>),
}

/// Encodes `payload` into a single Git pkt-line (`<4-hex-len><payload>`).
///
/// Panics if `payload.len() > 65516`, which exceeds Git's maximum pkt-line length (65520).
pub fn encode_pkt_line(payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() <= MAX_PKT_PAYLOAD,
        "pkt-line payload length {} exceeds maximum {MAX_PKT_PAYLOAD}",
        payload.len()
    );
    let total_len = payload.len() + 4;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(format!("{total_len:04x}").as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Returns the Git pkt-line flush packet (`b"0000"`).
pub fn encode_flush_pkt() -> Vec<u8> {
    FLUSH_PKT.to_vec()
}

/// Returns the Git pkt-line delimiter packet (`b"0001"`).
pub fn encode_delim_pkt() -> Vec<u8> {
    DELIM_PKT.to_vec()
}

/// Decodes a sequence of Git pkt-line frames from `input`.
pub fn decode_pkt_lines(input: &[u8]) -> Result<Vec<PktLine>> {
    let mut frames = Vec::new();
    let mut pos = 0;

    while pos < input.len() {
        if input.len() - pos < 4 {
            return Err(GitxError::GitBridge(
                "truncated pkt-line length prefix".to_string(),
            ));
        }
        let len_str = std::str::from_utf8(&input[pos..pos + 4]).map_err(|e| {
            GitxError::GitBridge(format!("non-UTF8 pkt-line length prefix: {e}"))
        })?;
        let len = usize::from_str_radix(len_str, 16).map_err(|e| {
            GitxError::GitBridge(format!("invalid pkt-line hex length '{len_str}': {e}"))
        })?;
        pos += 4;

        match len {
            0 => frames.push(PktLine::Flush),
            1 => frames.push(PktLine::Delim),
            2 => frames.push(PktLine::ResponseEnd),
            3 => {
                return Err(GitxError::GitBridge(
                    "invalid reserved pkt-line length 0003".to_string(),
                ));
            }
            n => {
                let payload_len = n - 4;
                if input.len() - pos < payload_len {
                    return Err(GitxError::GitBridge(format!(
                        "truncated pkt-line payload: expected {payload_len} bytes, got {}",
                        input.len() - pos
                    )));
                }
                frames.push(PktLine::Data(input[pos..pos + payload_len].to_vec()));
                pos += payload_len;
            }
        }
    }

    Ok(frames)
}

/// Builds the full Git Smart HTTP response body for `GET /info/refs?service=git-upload-pack`
/// against a projected bare Git repository.
pub fn advertise_upload_pack_refs(bare_git_dir: &Path) -> Result<Vec<u8>> {
    advertise_upload_pack_refs_with_protocol(bare_git_dir, None)
}

/// Same as [`advertise_upload_pack_refs`], optionally forwarding the `Git-Protocol` HTTP header
/// (e.g. `"version=2"`) via the `GIT_PROTOCOL` environment variable.
pub fn advertise_upload_pack_refs_with_protocol(
    bare_git_dir: &Path,
    git_protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(["upload-pack", "--stateless-rpc", "--advertise-refs"])
        .arg(bare_git_dir);
    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitxError::GitBridge(format!(
            "git upload-pack --advertise-refs failed: {}",
            stderr.trim()
        )));
    }

    let mut body = encode_pkt_line(b"# service=git-upload-pack\n");
    body.extend_from_slice(&encode_flush_pkt());
    body.extend_from_slice(&output.stdout);
    Ok(body)
}

/// Handles a Git Smart HTTP `POST /git-upload-pack` request body by invoking
/// `git upload-pack --stateless-rpc <bare_git_dir>` and returning the packfile/negotiation response.
pub fn handle_upload_pack(bare_git_dir: &Path, request_body: &[u8]) -> Result<Vec<u8>> {
    handle_upload_pack_with_protocol(bare_git_dir, request_body, None)
}

/// Same as [`handle_upload_pack`], optionally forwarding the `Git-Protocol` HTTP header.
pub fn handle_upload_pack_with_protocol(
    bare_git_dir: &Path,
    request_body: &[u8],
    git_protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(["upload-pack", "--stateless-rpc"])
        .arg(bare_git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let body = request_body.to_vec();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            match stdin.write_all(&body) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(err) => return Err(err),
            }
            match stdin.flush() {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(err) => return Err(err),
            }
            drop(stdin);
            Ok(())
        });
        let output = child.wait_with_output()?;
        let write_res = writer.join().map_err(|_| {
            GitxError::GitBridge("git upload-pack stdin writer thread panicked".into())
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitxError::GitBridge(format!(
                "git upload-pack --stateless-rpc failed: {}",
                stderr.trim()
            )));
        }
        write_res?;
        return Ok(output.stdout);
    }

    Err(GitxError::GitBridge(
        "failed to open stdin for git upload-pack".to_string(),
    ))
}

/// Builds the full Git Smart HTTP response body for `GET /info/refs?service=git-receive-pack`
/// against a projected bare Git repository.
pub fn advertise_receive_pack_refs_with_protocol(
    bare_git_dir: &Path,
    git_protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(["receive-pack", "--stateless-rpc", "--advertise-refs"])
        .arg(bare_git_dir);
    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitxError::GitBridge(format!(
            "git receive-pack --advertise-refs failed: {}",
            stderr.trim()
        )));
    }

    let mut body = encode_pkt_line(b"# service=git-receive-pack\n");
    body.extend_from_slice(&encode_flush_pkt());
    body.extend_from_slice(&output.stdout);
    Ok(body)
}

/// Handles a Git Smart HTTP `POST /git-receive-pack` request body by invoking
/// `git receive-pack --stateless-rpc <bare_git_dir>` and returning the status report.
pub fn handle_receive_pack_with_protocol(
    bare_git_dir: &Path,
    request_body: &[u8],
    git_protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(["receive-pack", "--stateless-rpc"])
        .arg(bare_git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let body = request_body.to_vec();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            match stdin.write_all(&body) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(err) => return Err(err),
            }
            match stdin.flush() {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(err) => return Err(err),
            }
            drop(stdin);
            Ok(())
        });
        let output = child.wait_with_output()?;
        let write_res = writer.join().map_err(|_| {
            GitxError::GitBridge("git receive-pack stdin writer thread panicked".into())
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitxError::GitBridge(format!(
                "git receive-pack --stateless-rpc failed: {}",
                stderr.trim()
            )));
        }
        write_res?;
        return Ok(output.stdout);
    }

    Err(GitxError::GitBridge(
        "failed to open stdin for git receive-pack".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_encode_decode_roundtrip() {
        let mut wire = encode_pkt_line(b"# service=git-upload-pack\n");
        assert_eq!(wire, b"001e# service=git-upload-pack\n");
        wire.extend_from_slice(&encode_flush_pkt());
        wire.extend_from_slice(&encode_pkt_line(b"version 2\n"));
        wire.extend_from_slice(&encode_delim_pkt());
        wire.extend_from_slice(&encode_pkt_line(b""));
        wire.extend_from_slice(&encode_flush_pkt());

        let decoded = decode_pkt_lines(&wire).unwrap();
        assert_eq!(
            decoded,
            vec![
                PktLine::Data(b"# service=git-upload-pack\n".to_vec()),
                PktLine::Flush,
                PktLine::Data(b"version 2\n".to_vec()),
                PktLine::Delim,
                PktLine::Data(Vec::new()),
                PktLine::Flush,
            ]
        );
    }
}
