"""Utility functions for address validation, source sanitization, and formatting."""

import re
from pathlib import Path
from typing import Tuple, Optional


def is_valid_eth_address(address: str) -> bool:
    """
    Check if a string is a valid Ethereum / EVM address format (0x + 40 hex chars).
    Supports both lowercase/uppercase and EIP-55 checksum addresses.
    """
    if not isinstance(address, str):
        return False
    address = address.strip()
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))


def _keccak_256(data: bytes) -> bytes:
    """Pure-Python Keccak-256 implementation (FIPS-202 Keccak with 0x01 padding)."""
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    r = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]
    rate = 136  # 1088 bits // 8
    padlen = rate - (len(data) % rate)
    if padlen == 1:
        padded = data + b"\x81"
    else:
        padded = data + b"\x01" + b"\x00" * (padlen - 2) + b"\x80"

    state = [[0] * 5 for _ in range(5)]
    for block_start in range(0, len(padded), rate):
        block = padded[block_start : block_start + rate]
        for i in range(len(block) // 8):
            x = i % 5
            y = i // 5
            val = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[x][y] ^= val

        for round_idx in range(24):
            # Theta
            C = [
                state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
                for x in range(5)
            ]
            D = [
                C[(x - 1) % 5]
                ^ (((C[(x + 1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) | (C[(x + 1) % 5] >> 63))
                for x in range(5)
            ]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]
            # Rho & Pi
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    rot = r[x][y]
                    val = state[x][y]
                    B[y][(2 * x + 3 * y) % 5] = (
                        (val << rot) & 0xFFFFFFFFFFFFFFFF
                    ) | (val >> (64 - rot) if rot else 0)
            # Chi
            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
            # Iota
            state[0][0] ^= RC[round_idx]

    out = bytearray()
    for y in range(5):
        for x in range(5):
            out.extend(state[x][y].to_bytes(8, "little"))
            if len(out) >= 32:
                return bytes(out[:32])
    return bytes(out[:32])


def to_checksum_address_safe(address: str) -> str:
    """
    Convert an address to EIP-55 checksum format.
    Uses Web3 if installed; otherwise falls back to native Pure-Python Keccak-256.
    """
    if not is_valid_eth_address(address):
        raise ValueError(f"Invalid EVM address format: {address}")

    clean = address.lower().replace("0x", "")

    # Try web3 first
    try:
        from web3 import Web3
        return Web3.to_checksum_address("0x" + clean)
    except Exception:
        pass

    # Try Crypto.Hash.keccak
    try:
        import Crypto.Hash.keccak as keccak
        k = keccak.new(digest_bits=256)
        k.update(clean.encode("ascii"))
        hash_hex = k.hexdigest()
    except Exception:
        # Robust Pure-Python fallback guaranteed to work in any Python 3.11+ environment
        hash_hex = _keccak_256(clean.encode("ascii")).hex()

    checksummed = ""
    for char, hash_char in zip(clean, hash_hex):
        if int(hash_char, 16) >= 8:
            checksummed += char.upper()
        else:
            checksummed += char.lower()
    return "0x" + checksummed


def is_valid_bytecode(bytecode: str) -> bool:
    """Check if the provided string is valid hex-encoded EVM bytecode."""
    if not isinstance(bytecode, str):
        return False
    cleaned = bytecode.strip()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return len(cleaned) > 0 and len(cleaned) % 2 == 0 and bool(re.match(r"^[0-9a-fA-F]+$", cleaned))


def sanitize_source_code(source: str) -> str:
    """
    Sanitizes source code: ensures UTF-8 encoding, normalizes newline characters,
    and strips carriage returns. Preserves code structure and comments for line indexing.
    """
    if not source:
        return ""
    # Normalize Windows and Mac carriage returns to Unix newlines
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    return normalized


def strip_comments(source: str) -> str:
    """
    Remove Solidity single-line (//) and multi-line (/* */) comments
    while preserving original line counts (substituting empty lines).
    This ensures accurate line numbers during regex and pattern detection.
    """
    def replacer(match):
        s = match.group(0)
        if s.startswith("/"):
            # Replace lines with empty lines to preserve line count
            return "\n" * s.count("\n")
        return s

    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, source)


def read_file_safe(file_path: Path, max_size_kb: int = 2048) -> Tuple[bool, str, Optional[str]]:
    """
    Safely read a file with size validation and encoding fallbacks.
    Returns: (success: bool, content_or_error: str, filename: Optional[str])
    """
    path = Path(file_path)
    if not path.exists():
        return False, f"File not found: {path}", None
    if not path.is_file():
        return False, f"Path is not a regular file: {path}", None

    size_kb = path.stat().st_size / 1024
    if size_kb > max_size_kb:
        return False, f"File size ({size_kb:.1f} KB) exceeds limit of {max_size_kb} KB.", path.name

    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=encoding) as f:
                content = f.read()
            return True, sanitize_source_code(content), path.name
        except UnicodeDecodeError:
            continue
        except Exception as e:
            return False, f"Error reading file {path}: {str(e)}", path.name

    return False, f"Failed to decode file {path} with supported encodings.", path.name
