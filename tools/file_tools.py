"""File inspection tools for downloaded artifacts."""
import base64
import os

from config import ARTIFACTS_DIR

# Filenames/patterns that must never be read regardless of location
_DENY_PATTERNS = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".key",
    "shadow", "/.ssh/", ".env", ".bash_history", ".zsh_history",
    "credentials", ".aws/", ".git-credentials", "wp-config.php",
)


def _is_safe_path(path: str) -> bool:
    """
    Restrict reads to the artifacts dir, temp dirs, and wordlist dirs only.
    Deliberately excludes /home/ — a broad /home/ allowance would let the
    server read SSH keys, .env files, shell history, etc. for any user.

    Uses realpath (resolves symlinks) so a symlink planted under an allowed
    dir cannot point at a sensitive file outside it, and commonpath so that
    e.g. '/tmpsecret' does not satisfy the '/tmp' prefix.
    """
    real_path = os.path.realpath(path)
    low = real_path.lower()

    # Defense-in-depth: block sensitive filenames even inside allowed dirs
    if any(pat in low for pat in _DENY_PATTERNS):
        return False

    allowed_prefixes = [
        os.path.realpath(ARTIFACTS_DIR),
        "/tmp",
        "/var/tmp",
        "/usr/share/wordlists",
        "/usr/share/seclists",
    ]
    for prefix in allowed_prefixes:
        real_prefix = os.path.realpath(prefix)
        try:
            if os.path.commonpath([real_prefix, real_path]) == real_prefix:
                return True
        except ValueError:
            # Different drives / mix of abs+rel — not a match
            continue
    return False


def _detect_magic(data: bytes) -> str:
    """Detect file type from magic bytes."""
    if data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4"):
        return "pcap (libpcap)"
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng"
    if data.startswith(b"\x7fELF"):
        return "ELF binary"
    if data.startswith(b"MZ"):
        return "PE/DOS executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\x89PNG"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"#!"):
        return "script (shebang: " + data.split(b"\n", 1)[0].decode(errors="replace") + ")"
    # Detect text
    try:
        data[:100].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def _register(mcp, job_mgr):

    @mcp.tool()
    async def read_file(
        path: str,
        max_bytes: int = 50000,
        offset: int = 0,
        as_hex: bool = False,
        as_base64: bool = False,
    ) -> dict:
        """
        Read a file from disk (artifacts, /tmp, /var/tmp, wordlists).
        Auto-detects file type via magic bytes.
        path: absolute file path
        max_bytes: max bytes to read (default 50KB)
        offset: byte offset to start from
        as_hex: return content as hex dump
        as_base64: return content as base64 (for binaries)
        Returns: file metadata, type detection, content (text/hex/base64)
        """
        if not _is_safe_path(path):
            return {
                "error": f"Path not allowed: {path}",
                "hint": "Only paths under /tmp, /var/tmp, /usr/share/wordlists, /usr/share/seclists, and the artifacts dir are readable",
            }
        if not os.path.exists(path):
            return {"error": f"File not found: {path}"}

        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(max_bytes)

        magic = _detect_magic(data)
        result = {
            "path": path,
            "size_bytes": size,
            "read_bytes": len(data),
            "offset": offset,
            "type": magic,
            "truncated": size > offset + len(data),
        }

        if as_hex:
            result["hex"] = data.hex()
        elif as_base64:
            result["base64"] = base64.b64encode(data).decode()
        elif magic.startswith(("binary", "ELF", "PE", "ZIP", "PNG", "JPEG", "PDF", "pcap")):
            # Default to hex for binaries
            result["hex_preview"] = data[:1024].hex()
            result["note"] = f"Binary content ({magic}). Use as_hex=True or as_base64=True for full content."
        else:
            try:
                result["content"] = data.decode("utf-8", errors="replace")
            except Exception:
                result["hex"] = data.hex()

        return result

    @mcp.tool()
    async def list_artifacts() -> dict:
        """
        List all files in the artifacts directory (downloads, scan outputs, payloads).
        Returns: filename, size, modification time per file.
        """
        if not os.path.exists(ARTIFACTS_DIR):
            return {"artifacts": [], "dir": ARTIFACTS_DIR}
        files = []
        for name in sorted(os.listdir(ARTIFACTS_DIR)):
            path = os.path.join(ARTIFACTS_DIR, name)
            if os.path.isfile(path):
                stat = os.stat(path)
                files.append({
                    "name": name,
                    "path": path,
                    "size_bytes": stat.st_size,
                    "modified": stat.st_mtime,
                })
        return {"dir": ARTIFACTS_DIR, "count": len(files), "artifacts": files}
