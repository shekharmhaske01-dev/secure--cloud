"""Integrity verification for stored files.

Two layers are used:

1. **Authenticated encryption (primary).**  Every block carries a GCM tag over
   the ciphertext plus AAD binding it to ``(format version, file id, block
   index)``.  A checksum is therefore *not* the integrity mechanism - the
   AEAD tag is, and any tampering is rejected before plaintext is released.
2. **Manifest checks (secondary).**  Block count, contiguity of sequence
   numbers, per-block sizes and the presence/size of every stored object are
   validated against the SQLite metadata so that missing or substituted
   objects are detected early, with a clear diagnosis.

The optional plaintext SHA-256 stored for each file is a convenience check for
the whole reconstructed file; it never replaces the per-block AEAD tag.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from securecloud.services import FileIntegrityError
from securecloud.services import chunking, encryption, storage_service as storage_service_module

MANIFEST_VERSION = 1


@dataclass
class IntegrityReport:
    ok: bool = True
    file_id: int | None = None
    public_id: str | None = None
    filename: str | None = None
    block_count_expected: int = 0
    block_count_found: int = 0
    total_size_expected: int = 0
    total_size_found: int = 0
    order_ok: bool = True
    encrypted_size_ok: bool = True
    objects_present: bool = True
    authenticated: bool | None = None
    deep: bool = False
    problems: list[str] = field(default_factory=list)
    missing_objects: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)

    def add_check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            self.ok = False

    def fail(self, message: str) -> None:
        self.ok = False
        self.problems.append(message)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "manifest_version": MANIFEST_VERSION,
            "file_id": self.file_id,
            "public_id": self.public_id,
            "filename": self.filename,
            "deep": self.deep,
            "block_count_expected": self.block_count_expected,
            "block_count_found": self.block_count_found,
            "total_size_expected": self.total_size_expected,
            "total_size_found": self.total_size_found,
            "order_ok": self.order_ok,
            "encrypted_size_ok": self.encrypted_size_ok,
            "objects_present": self.objects_present,
            "authenticated": self.authenticated,
            "missing_objects": self.missing_objects,
            "problems": self.problems,
            "checks": self.checks,
        }


def expected_plaintext_size(index: int, block_size: int, total_size: int, block_count: int) -> int:
    if block_count == 0:
        return 0
    if index == block_count - 1:
        return total_size - index * block_size
    return block_size


def verify_manifest(file, storage_service, *, deep: bool = False, key_manager=None) -> IntegrityReport:
    """Validate the metadata manifest and (optionally) the objects themselves."""
    report = IntegrityReport(
        file_id=file.id,
        public_id=file.public_id,
        filename=file.original_filename,
        block_count_expected=file.block_count or 0,
        total_size_expected=file.file_size or 0,
        deep=deep,
    )

    blocks = sorted(file.blocks, key=lambda b: b.block_index)
    report.block_count_found = len(blocks)
    report.total_size_found = sum(b.plaintext_size or 0 for b in blocks)

    report.add_check(
        "block_count",
        report.block_count_found == report.block_count_expected,
        f"metadata={report.block_count_expected} found={report.block_count_found}",
    )
    if report.block_count_found != report.block_count_expected:
        report.fail(
            f"Expected {report.block_count_expected} blocks but the manifest lists "
            f"{report.block_count_found}."
        )

    indexes = [b.block_index for b in blocks]
    report.order_ok = indexes == list(range(len(indexes)))
    report.add_check("block_order", report.order_ok, f"indexes={indexes[:10]}{'...' if len(indexes) > 10 else ''}")
    if not report.order_ok:
        report.fail("Block sequence numbers are not contiguous starting at 0.")

    size_ok = True
    for block in blocks:
        expected = expected_plaintext_size(
            block.block_index, file.block_size, file.file_size, file.block_count
        )
        if block.plaintext_size != expected:
            size_ok = False
            break
    report.encrypted_size_ok = size_ok
    report.add_check("plaintext_sizes", size_ok, "per-block plaintext sizes match the plan")
    if not size_ok:
        report.fail("One or more blocks report an unexpected plaintext size.")

    overhead_ok = all(
        (b.encrypted_size or 0) == (b.plaintext_size or 0) + encryption.GCM_TAG_BYTES for b in blocks
    )
    report.add_check(
        "aead_overhead",
        overhead_ok,
        f"each encrypted block = plaintext + {encryption.GCM_TAG_BYTES} byte tag",
    )
    if not overhead_ok:
        report.fail("A stored block has an unexpected encrypted size (AEAD overhead).")

    report.add_check(
        "reconstructed_length",
        report.total_size_found == report.total_size_expected,
        f"metadata={report.total_size_expected} manifest={report.total_size_found}",
    )
    if report.total_size_found != report.total_size_expected:
        report.fail("The sum of block sizes does not match the recorded file size.")

    if file.wrapped_key is None and file.block_count:
        report.fail("No wrapped data-encryption key is stored for this file.")
        report.add_check("wrapped_key", False, "missing")
    else:
        report.add_check("wrapped_key", True, "present")

    # --- object presence / size ------------------------------------------
    missing: list[str] = []
    for block in blocks:
        try:
            info = storage_service.object_info(block.object_key)
        except Exception as exc:  # provider failure must not look like success
            report.add_check("object_presence", False, f"{type(exc).__name__}")
            report.fail("Object storage could not be queried while verifying this file.")
            return report
        if not info.get("exists"):
            missing.append(block.object_key)
            continue
        actual = info.get("size")
        if actual is not None and actual != block.encrypted_size:
            report.fail(f"Stored object for block {block.block_index} has an unexpected size.")
            report.add_check("object_size", False, f"index={block.block_index}")
    report.missing_objects = missing
    report.objects_present = not missing
    report.add_check(
        "objects_present",
        report.objects_present,
        f"{len(blocks) - len(missing)}/{len(blocks)} objects found",
    )
    if missing:
        report.fail("One or more encrypted blocks are missing from object storage.")

    if not deep:
        return report

    # --- deep: authenticate and decrypt every block -----------------------
    if key_manager is None:
        from securecloud.services.key_manager import get_key_manager

        key_manager = get_key_manager()
    if file.wrapped_key is None:
        report.authenticated = False
        report.add_check("authentication", False, "no wrapped key available")
        return report
    try:
        dek = key_manager.unwrap_dek(
            file.wrapped_key.wrapped_dek,
            file.wrapped_key.wrap_nonce,
            file.wrapped_key.wrap_format_version,
        )
    except Exception as exc:
        report.authenticated = False
        report.add_check("key_unwrap", False, type(exc).__name__)
        report.fail("The stored file key could not be unwrapped with the configured KEK.")
        return report
    report.add_check("key_unwrap", True, "wrapped key authenticated")

    digest = hashlib.sha256()
    written = 0
    try:
        for block in blocks:
            ciphertext = storage_service.fetch_block(block.object_key)
            plaintext = encryption.decrypt_block(
                dek,
                block.nonce,
                ciphertext,
                file.public_id,
                block.block_index,
                block.format_version,
            )
            if len(plaintext) != block.plaintext_size:
                raise FileIntegrityError("A block decrypted to an unexpected length.")
            digest.update(plaintext)
            written += len(plaintext)
        report.authenticated = True
        report.add_check("authentication", True, "every block authenticated and decrypted")
    except Exception as exc:
        report.authenticated = False
        report.add_check("authentication", False, type(exc).__name__)
        report.fail(f"Block authentication failed: {getattr(exc, 'public_message', str(exc))}")
        return report
    finally:
        dek = None  # noqa: F841 - drop the plaintext key reference

    if written != report.total_size_expected:
        report.fail("Authenticated content length does not match the recorded file size.")
    if file.plaintext_sha256:
        report.add_check(
            "plaintext_sha256",
            digest.hexdigest() == file.plaintext_sha256,
            "whole-file digest matches the value recorded at upload time",
        )
    return report


def verify_reconstruction(*, blocks: list, file, key_manager) -> dict:
    """Reconstruct in memory and confirm byte-for-byte integrity (used by tests)."""
    if file.wrapped_key is None:
        raise FileIntegrityError("No wrapped key stored for this file.")
    dek = key_manager.unwrap_dek(
        file.wrapped_key.wrapped_dek,
        file.wrapped_key.wrap_nonce,
        file.wrapped_key.wrap_format_version,
    )
    out = bytearray()
    for block in sorted(blocks, key=lambda b: b.block_index):
        ciphertext = storage_service_module.get_storage_service().fetch_block(block.object_key)
        out += encryption.decrypt_block(
            dek, block.nonce, ciphertext, file.public_id, block.block_index, block.format_version
        )
    expected = file.plaintext_sha256
    actual = hashlib.sha256(bytes(out)).hexdigest()
    return {
        "size": len(out),
        "sha256": actual,
        "matches_recorded": (actual == expected) if expected else None,
    }


__all__ = [
    "IntegrityReport",
    "MANIFEST_VERSION",
    "chunking",
    "expected_plaintext_size",
    "verify_manifest",
    "verify_reconstruction",
]
