"""File segmentation (chunking) and reconstruction.

Files are read incrementally so that memory use stays bounded by the block
size, and are split into blocks of ``BLOCK_SIZE`` bytes (default 1 MiB).
Blocks are never assumed to be returned in order: reconstruction always sorts
by the verified ``block_index`` metadata.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Iterator, Iterable, Sequence

from securecloud.services import FileIntegrityError, FileValidationError

DEFAULT_BLOCK_SIZE = 1024 * 1024
MIN_BLOCK_SIZE = 4096
MAX_BLOCK_SIZE = 64 * 1024 * 1024
READ_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class BlockPlan:
    """Pre-computed segmentation plan for a file of a known size."""

    block_size: int
    block_count: int
    total_size: int

    @property
    def final_block_size(self) -> int:
        if self.block_count == 0:
            return 0
        remainder = self.total_size - (self.block_count - 1) * self.block_size
        return remainder

    @property
    def has_partial_final_block(self) -> bool:
        return self.block_count > 0 and self.final_block_size != self.block_size


def validate_block_size(block_size: int) -> int:
    try:
        size = int(block_size)
    except (TypeError, ValueError) as exc:
        raise FileValidationError("Invalid block size configuration.") from exc
    if size < MIN_BLOCK_SIZE or size > MAX_BLOCK_SIZE:
        raise FileValidationError(
            "Block size must be between 4 KiB and 64 MiB.",
            detail=f"configured={size}",
        )
    return size


def count_blocks(total_size: int, block_size: int) -> int:
    """Number of blocks for *total_size* bytes (0 for an empty file)."""
    if total_size < 0:
        raise FileValidationError("File size cannot be negative.")
    if total_size == 0:
        return 0
    return (total_size + block_size - 1) // block_size


def plan_for_size(total_size: int, block_size: int) -> BlockPlan:
    return BlockPlan(block_size=block_size, block_count=count_blocks(total_size, block_size), total_size=total_size)


def iter_file_blocks(path: str, block_size: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(index, block)`` for a file on disk, reading incrementally."""
    index = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(block_size)
            if not chunk:
                break
            yield index, chunk
            index += 1


def iter_stream_blocks(stream, block_size: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(index, block)`` from a binary stream."""
    index = 0
    while True:
        chunk = stream.read(block_size)
        if not chunk:
            break
        yield index, chunk
        index += 1


def iter_bytes_blocks(data: bytes, block_size: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(index, block)`` from an in-memory buffer (used by tests)."""
    index = 0
    view = memoryview(data)
    while index * block_size < len(data):
        start = index * block_size
        yield index, bytes(view[start:start + block_size])
        index += 1


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_stream_to_file(stream, dest_path: str, max_bytes: int | None = None) -> dict:
    """Copy an upload stream to *dest_path*, computing size and SHA-256.

    The stream is copied in bounded chunks.  When *max_bytes* is exceeded the
    partially written file is removed and a validation error is raised, so an
    oversized upload can never be staged.
    """
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = stream.read(READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise FileValidationError(
                        "The selected file exceeds the maximum allowed upload size.",
                        detail=f"limit={max_bytes}",
                    )
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        remove_quietly(dest_path)
        raise
    return {"size": total, "sha256": digest.hexdigest()}


def remove_quietly(path: str | None) -> None:
    """Delete a file, ignoring errors (used for staging/temp cleanup)."""
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass


class Reconstructor:
    """Reassemble a file from decrypted blocks while enforcing ordering.

    Blocks may arrive in any order; each is written at its offset derived from
    the verified block index, so nothing depends on the storage provider
    returning objects in sequence.  Sizes are tracked per block so the final
    length check is independent of the delivery order.
    """

    def __init__(self, output_stream, block_size: int, expected_block_count: int,
                 expected_total_size: int):
        self.output_stream = output_stream
        self.block_size = block_size
        self.expected_block_count = expected_block_count
        self.expected_total_size = expected_total_size
        self.sizes: dict[int, int] = {}
        self.duplicates: list[int] = []
        self.last_index = -1

    @property
    def written(self) -> int:
        """Total number of plaintext bytes accepted so far."""
        return sum(self.sizes.values())

    def add(self, block_index: int, plaintext: bytes) -> None:
        if block_index < 0 or block_index >= max(self.expected_block_count, 1):
            raise FileIntegrityError(
                "A block with an unexpected sequence number was returned.",
                detail=f"index={block_index} expected_count={self.expected_block_count}",
            )
        if block_index in self.sizes:
            # A replayed block: remember it instead of overwriting, and let
            # finish() report the anomaly.
            self.duplicates.append(block_index)
            return
        offset = block_index * self.block_size
        self.output_stream.seek(offset)
        self.output_stream.write(plaintext)
        self.output_stream.seek(0, os.SEEK_END)
        self.sizes[block_index] = len(plaintext)
        self.last_index = max(self.last_index, block_index)

    def finish(self) -> dict:
        if self.duplicates:
            raise FileIntegrityError(
                "A duplicate block was returned by object storage.",
                detail=f"indexes={sorted(set(self.duplicates))[:20]}",
            )
        missing = sorted(set(range(self.expected_block_count)) - set(self.sizes))
        if missing:
            raise FileIntegrityError(
                "The stored file is incomplete: one or more blocks are missing.",
                detail=f"missing indexes={missing[:20]}",
            )
        total = self.written
        if total != self.expected_total_size:
            raise FileIntegrityError(
                "The reconstructed file length does not match the original.",
                detail=f"reconstructed={total} expected={self.expected_total_size}",
            )
        if self.expected_block_count == 0 and self.output_stream.seekable():
            self.output_stream.seek(0)
            self.output_stream.truncate(0)
        self.output_stream.flush()
        return {
            "block_count": len(self.sizes),
            "total_size": total,
            "ordered": self.last_index == self.expected_block_count - 1,
        }


def verify_block_sizes(blocks: Sequence, block_size: int, total_size: int) -> list[str]:
    """Return a list of size/ordering problems for a block manifest."""
    problems: list[str] = []
    indexes = sorted(b.block_index for b in blocks)
    if indexes != list(range(len(indexes))):
        problems.append("Block sequence numbers are not contiguous starting at 0.")
    for i, block in enumerate(sorted(blocks, key=lambda b: b.block_index)):
        expected = block_size
        if i == len(blocks) - 1 and total_size:
            expected = total_size - i * block_size
        if block.plaintext_size != expected:
            problems.append(f"Block {block.block_index} has unexpected plaintext size.")
    return problems


def assert_round_trip(original: bytes, chunks: Iterable[bytes]) -> bytes:
    """Test helper: join decrypted chunks and assert byte-for-byte equality."""
    rebuilt = b"".join(chunks)
    if rebuilt != original:
        raise FileIntegrityError("Round-trip verification failed.")
    return rebuilt
