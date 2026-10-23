"""
Automated Cryptographic & Workflow Verification Test Suite for FileGuard
"""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import core functions directly from crypto_engine
from crypto_engine import (
    calculate_hash,
    encrypt_file,
    decrypt_file,
    short_hash,
    load_or_create_key,
    load_metadata,
    save_metadata,
    SIMULATION_MARKER,
    DEMO_SAMPLE_TEXT,
)


def run_tests():
    print("==================================================")
    print(" RUNNING FILEGUARD COMPREHENSIVE TEST SUITE")
    print("==================================================")

    # 1. Key generation and length test
    key = AESGCM.generate_key(bit_length=256)
    assert len(key) == 32, "AES-256 key must be exactly 32 bytes"
    print(" [PASS] Test 1: 256-bit AES key generation & sizing verified.")

    # 2. SHA-256 Baseline & Determinism test
    sample_bytes = DEMO_SAMPLE_TEXT.encode("utf-8")
    original_hash = calculate_hash(sample_bytes)
    assert len(original_hash) == 64, "SHA-256 hex digest must be 64 characters"
    assert calculate_hash(sample_bytes) == original_hash, "Hashing must be deterministic"
    print(f" [PASS] Test 2: SHA-256 baseline calculation verified: {short_hash(original_hash)}")

    # 3. AES-256-GCM Encryption & Decryption test
    encrypted_blob = encrypt_file(sample_bytes, key)
    assert len(encrypted_blob) == 12 + len(sample_bytes) + 16, "Blob must contain 12-byte nonce + ciphertext + 16-byte tag"
    decrypted_bytes = decrypt_file(encrypted_blob, key)
    assert decrypted_bytes == sample_bytes, "Decrypted bytes must match original plaintext exactly"
    print(" [PASS] Test 3: AES-256-GCM authenticated encryption and decryption verified.")

    # 4. AEAD Tamper Resistance (InvalidTag test)
    tampered_blob = bytearray(encrypted_blob)
    tampered_blob[-1] ^= 0x01  # Flip one bit in the authentication tag
    try:
        decrypt_file(bytes(tampered_blob), key)
        assert False, "Decryption should have raised InvalidTag upon tampering"
    except InvalidTag:
        print(" [PASS] Test 4: AEAD integrity check correctly threw InvalidTag when ciphertext was tampered.")

    # 5. File Protection and Folder Separation Test
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        orig_dir = tmp_path / "originals"
        enc_dir = tmp_path / "encrypted"
        bak_dir = tmp_path / "backups"
        orig_dir.mkdir()
        enc_dir.mkdir()
        bak_dir.mkdir()

        file_id = "test_doc_001"
        working_file = orig_dir / file_id
        backup_file = bak_dir / file_id
        enc_file = enc_dir / f"{file_id}.enc"

        # Save files
        working_file.write_bytes(sample_bytes)
        shutil.copyfile(working_file, backup_file)
        enc_file.write_bytes(encrypt_file(sample_bytes, key))

        # Check hashes
        assert calculate_hash(working_file.read_bytes()) == original_hash
        assert calculate_hash(backup_file.read_bytes()) == original_hash
        print(" [PASS] Test 5: Working copy, backup copy, and encrypted vault separated successfully.")

        # 6. Attack Simulation: Only working copy is modified
        working_file.write_bytes(working_file.read_bytes() + SIMULATION_MARKER)
        modified_hash = calculate_hash(working_file.read_bytes())

        assert modified_hash != original_hash, "Working copy hash must change after attack simulation"
        assert calculate_hash(backup_file.read_bytes()) == original_hash, "Backup copy MUST NOT be altered during attack!"
        assert decrypt_file(enc_file.read_bytes(), key) == sample_bytes, "Encrypted vault MUST NOT be altered during attack!"
        print(f" [PASS] Test 6: Attack simulation changed working copy ({short_hash(modified_hash)}) while backup & vault stayed intact.")

        # 7. Detection Scan: Compare working copy with baseline
        scan_match = (calculate_hash(working_file.read_bytes()) == original_hash)
        assert not scan_match, "Security scan must detect hash discrepancy!"
        print(" [PASS] Test 7: Security scan successfully detected unauthorized modification.")

        # 8. Corrupted Backup Defense Test
        corrupted_backup = backup_file.read_bytes() + b"[CORRUPTED]"
        assert calculate_hash(corrupted_backup) != original_hash, "Corrupted backup hash must not match"
        print(" [PASS] Test 8: Pre-restoration integrity check detects simulated corrupted backup.")

        # 9. Verified Backup Recovery Test
        # Pre-check original backup
        assert calculate_hash(backup_file.read_bytes()) == original_hash, "Backup integrity verified"
        # Restore
        working_file.write_bytes(backup_file.read_bytes())
        restored_hash = calculate_hash(working_file.read_bytes())
        assert restored_hash == original_hash, "Restored working file must match original baseline exactly"
        print(" [PASS] Test 9: Backup restoration verified and working copy recovered to original baseline.")

        # 10. Post-Recovery Scan Test
        post_scan_match = (calculate_hash(working_file.read_bytes()) == original_hash)
        assert post_scan_match, "Post-recovery security scan must pass."
        print(" [PASS] Test 10: Post-recovery security scan passed with green baseline integrity.")

    print("==================================================")
    print(" ALL 10 TESTS PASSED SUCCESSFULLY! ")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
