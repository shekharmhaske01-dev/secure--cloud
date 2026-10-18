"""File segmentation (chunking) and reconstruction tests."""
from __future__ import annotations

import io
import os

import pytest

from securecloud.services import FileIntegrityError, FileValidationError
from securecloud.services import chunking
from securecloud.services.chunking import (
    Reconstructor,
    count_blocks,
    iter_bytes_blocks,
    iter_file_blocks,
    plan_for_size,
    sha256_file,
    stage_stream_to_file,
    validate_block_size,
)

BLOCK = 4096


def test_count_blocks_covers_all_size_cases():
    assert count_blocks(0, BLOCK) == 0            # empty file
    assert count_blocks(1, BLOCK) == 1            # smaller than one block
    assert count_blocks(BLOCK - 1, BLOCK) == 1
    assert count_blocks(BLOCK, BLOCK) == 1        # exactly one block
    assert count_blocks(BLOCK + 1, BLOCK) == 2    # one full + partial final block
    assert count_blocks(BLOCK * 3, BLOCK) == 3
    assert count_blocks(BLOCK * 3 + 7, BLOCK) == 4


def test_plan_reports_partial_final_block():
    plan = plan_for_size(BLOCK * 2 + 123, BLOCK)
    assert plan.block_count == 3
    assert plan.final_block_size == 123
    assert plan.has_partial_final_block is True

    exact = plan_for_size(BLOCK * 2, BLOCK)
    assert exact.has_partial_final_block is False
    assert exact.final_block_size == BLOCK

    empty = plan_for_size(0, BLOCK)
    assert empty.block_count == 0
    assert empty.final_block_size == 0


def test_iter_bytes_blocks_preserves_every_byte():
    for size in (0, 1, BLOCK - 1, BLOCK, BLOCK + 1, BLOCK * 4, BLOCK * 4 + 999):
        data = os.urandom(size)
        blocks = list(iter_bytes_blocks(data, BLOCK))
        assert b"".join(block for _index, block in blocks) == data
        assert len(blocks) == count_blocks(size, BLOCK)
        assert [index for index, _ in blocks] == list(range(len(blocks)))


def test_iter_file_blocks_streams_in_order(tmp_path):
    path = tmp_path / "payload.bin"
    data = os.urandom(BLOCK * 3 + 500)
    path.write_bytes(data)
    blocks = list(iter_file_blocks(str(path), BLOCK))
    assert [index for index, _ in blocks] == [0, 1, 2, 3]
    assert len(blocks[0][1]) == BLOCK
    assert len(blocks[-1][1]) == 500
    assert b"".join(block for _i, block in blocks) == data


def test_reconstructor_accepts_out_of_order_blocks():
    """Blocks may arrive in any order; ordering comes from the metadata."""
    original = os.urandom(BLOCK * 3 + 321)
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 4, len(original))
    parts = {index: block for index, block in iter_bytes_blocks(original, BLOCK)}
    for index in (3, 0, 2, 1):
        reconstructor.add(index, parts[index])
    stats = reconstructor.finish()
    assert stats["block_count"] == 4
    assert stats["total_size"] == len(original)
    assert out.getvalue() == original


def test_reconstructor_detects_missing_block():
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 3, BLOCK * 3)
    reconstructor.add(0, b"a" * BLOCK)
    reconstructor.add(2, b"c" * BLOCK)
    with pytest.raises(FileIntegrityError):
        reconstructor.finish()


def test_reconstructor_detects_duplicate_block():
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 2, BLOCK * 2)
    reconstructor.add(0, b"a" * BLOCK)
    reconstructor.add(0, b"a" * BLOCK)
    with pytest.raises(FileIntegrityError):
        reconstructor.finish()


def test_reconstructor_detects_wrong_length():
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 1, BLOCK)
    reconstructor.add(0, b"short")
    with pytest.raises(FileIntegrityError):
        reconstructor.finish()


def test_reconstructor_rejects_out_of_range_index():
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 2, BLOCK * 2)
    with pytest.raises(FileIntegrityError):
        reconstructor.add(9, b"x" * BLOCK)


def test_empty_file_has_no_blocks_and_reconstructs():
    out = io.BytesIO()
    reconstructor = Reconstructor(out, BLOCK, 0, 0)
    stats = reconstructor.finish()
    assert stats["block_count"] == 0
    assert out.getvalue() == b""


def test_validate_block_size_bounds():
    assert validate_block_size(BLOCK) == BLOCK
    for bad in (1024, 0, -1, 128 * 1024 * 1024, "abc"):
        with pytest.raises(FileValidationError):
            validate_block_size(bad)


def test_stage_stream_enforces_max_bytes(tmp_path):
    dest = str(tmp_path / "staged.bin")
    payload = io.BytesIO(os.urandom(5000))
    with pytest.raises(FileValidationError):
        stage_stream_to_file(payload, dest, max_bytes=4000)
    assert not os.path.exists(dest), "an oversized upload must not leave a staged file"


def test_stage_stream_records_size_and_digest(tmp_path):
    dest = str(tmp_path / "staged.bin")
    data = os.urandom(9000)
    result = stage_stream_to_file(io.BytesIO(data), dest, max_bytes=20000)
    assert result["size"] == 9000
    assert result["sha256"] == sha256_file(dest)
    assert open(dest, "rb").read() == data


def test_sha256_of_file_matches_hashlib(tmp_path):
    import hashlib

    path = tmp_path / "x.bin"
    data = os.urandom(123456)
    path.write_bytes(data)
    assert sha256_file(str(path)) == hashlib.sha256(data).hexdigest()


def test_full_segmentation_round_trip_with_encryption():
    """Segment -> encrypt -> decrypt (any order) -> reassemble must be byte-identical."""
    from securecloud.services.encryption import decrypt_block, encrypt_block

    key = os.urandom(32)
    for size in (0, 1, BLOCK - 1, BLOCK, BLOCK + 1, BLOCK * 5 + 77):
        original = os.urandom(size)
        encrypted = {}
        for index, block in iter_bytes_blocks(original, BLOCK):
            nonce, ciphertext = encrypt_block(key, block, "file-uid", index)
            encrypted[index] = (nonce, ciphertext)
        # Deliberately shuffled delivery order.
        out = io.BytesIO()
        reconstructor = Reconstructor(out, BLOCK, len(encrypted), size)
        for index in sorted(encrypted, reverse=True):
            nonce, ciphertext = encrypted[index]
            plaintext = decrypt_block(key, nonce, ciphertext, "file-uid", index)
            reconstructor.add(index, plaintext)
        reconstructor.finish()
        assert out.getvalue() == original, f"round trip failed for size {size}"


def test_verify_block_sizes_flags_problems():
    class FakeBlock:
        def __init__(self, index, plaintext_size):
            self.block_index = index
            self.plaintext_size = plaintext_size

    good = [FakeBlock(0, BLOCK), FakeBlock(1, 100)]
    assert chunking.verify_block_sizes(good, BLOCK, BLOCK + 100) == []
    bad = [FakeBlock(0, 10), FakeBlock(1, 100)]
    assert chunking.verify_block_sizes(bad, BLOCK, BLOCK + 100)
    non_contiguous = [FakeBlock(1, BLOCK), FakeBlock(3, 100)]
    assert chunking.verify_block_sizes(non_contiguous, BLOCK, BLOCK + 100)
