# 🛡️ FileGuard — Ransomware-Resistant File Protection System

> **A Cryptography & Cybersecurity Microproject**  
> *Demonstrating AES-256-GCM Authenticated Encryption, SHA-256 Baseline Integrity Auditing, Controlled Attack Simulation, Discrepancy Detection, and Cryptographically Verified Recovery.*

---

## 📌 1. Project Overview

**FileGuard** is a security-focused microproject designed to protect sensitive endpoint documents against unauthorized modification and simulated ransomware tampering.

It demonstrates a defense-in-depth approach by combining:
1. **Authenticated Encryption (AES-256-GCM)**: Guarantees confidentiality and authenticity using 256-bit keys, unique 96-bit nonces, and 128-bit authentication tags.
2. **Cryptographic Baseline Hashing (SHA-256)**: Creates an immutable reference fingerprint to detect single-bit file alterations through the *Avalanche Effect*.
3. **Controlled Attack Simulation**: Safely demonstrates unauthorized file modification on a disposable working copy without damaging user files or system integrity.
4. **Endpoint Security Scanning**: Compares the real-time file digest against the trusted baseline to flag tampering and generate incident alerts.
5. **Verified Recovery**: Cryptographically validates the isolated backup's fingerprint before restoring the working copy, ensuring zero data loss and tamper-free recovery.

---

## 🏛️ 2. Architectural Design

```text
                               +----------------------------+
                               |     User / Application     |
                               +--------------+-------------+
                                              |
                          [Step 1: Protect File / Baseline]
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
           +--------------------+                            +--------------------+
           |  Working Copy      |                            |   Encrypted Vault  |
           | (data/originals/)  |                            |  (data/encrypted/) |
           +---------+----------+                            |    AES-256-GCM     |
                     |                                       +--------------------+
                     |  [Copies verified baseline]
                     v
           +--------------------+
           |   Trusted Backup   |
           |  (data/backups/)   |
           +--------------------+
                     |
       [Step 3: Attack Simulation]  ---> Alters ONLY Working Copy (Appends marker)
                     |                   Backup & Encrypted Vault remain INTACT!
                     v
       [Step 4: Security Scan]      ---> Calculates SHA-256 of Working Copy
                                         Compares with Trusted Baseline
                                         -> Triggers Red Security Alert
                     |
       [Step 6: Verified Recovery]  ---> 1. Check Backup SHA-256 == Baseline
                                         2. Restore Working Copy
                                         3. Re-verify SHA-256 on disk
                                         -> Working copy restored to clean state!
```

---

## 🔬 3. Cryptographic Primitives Explained

### A. AES-256-GCM (Galois/Counter Mode)
* **Type**: Symmetric Authenticated Encryption with Associated Data (AEAD).
* **Key Size**: 256 bits (32 bytes).
* **Nonce (IV)**: 96 bits (12 bytes) uniquely generated per operation using a cryptographically secure pseudo-random number generator (`os.urandom`).
* **Authentication Tag**: 128 bits (16 bytes) Galois MAC. Decryption automatically fails if any byte in the ciphertext or tag is modified.

### B. SHA-256 (Secure Hash Algorithm 256-bit)
* **Output**: Fixed 256-bit digest (64 hexadecimal characters).
* **Avalanche Effect**: Changing even a single character or bit in the source file changes approximately 50% of the resulting digest bits.
* **Role**: Rapid endpoint integrity check without requiring full-vault decryption.

---

## 🚀 4. Installation & Setup

### Prerequisites
* Python 3.10+ (tested on Python 3.12)
* Windows, macOS, or Linux

### Quick Start

1. **Activate the Virtual Environment**:
   ```powershell
   # On Windows (PowerShell)
   .\.venv\Scripts\Activate.ps1
   ```

2. **Run the Automated Test Suite**:
   ```bash
   python test_workflow.py
   ```

3. **Launch the FileGuard Security Console**:
   ```bash
   streamlit run app.py
   ```
   *The dashboard will automatically open in your default browser at `http://localhost:8501`.*

---

## 🎬 5. Step-by-Step Viva Demonstration Guide

Follow this sequence to present FileGuard to your professor:

### Step 1: Clean Dashboard & Protection Baseline
1. Open the dashboard at `http://localhost:8501`.
2. Notice the clean, evaluation-ready dashboard matching Image 2:
   * **Top Metric Cards**: `File Protection: Ready`, `Encryption: AES-256-GCM`, `Integrity Check: SHA-256`.
   * **Upload Your File**: File uploader with `🔐 Protect Uploaded File` and `📄 Quick Load Demo: Project_Report.txt`.
   * **Active Document**: Displays `Project_Report.txt` with trusted baseline fingerprint.
   * **5-Step Protection Flow**: Indicates Step 1 is verified.

### Step 2: Open & Maximize Attack Simulation
1. Click **"⚡ Run Attack Simulation"** in Quick Actions (or **"🗖 Expand Attack Simulation Side Window"**).
2. The Attack Simulation window opens:
   * **1. Original File (Read Only)**: Lines 1, 2, 3 (`Project Name: FileGuard`, `Original marks: 80`, `Status: Approved`).
   * **2. Working Copy (Being Modified)**: Live document representation.
   * **Controls**: You can click **"🗖 Full Window View"** or **"🗗 Side-by-Side Split"** according to your preference!

### Step 3: Simulate Unauthorized Hacker Modification
1. Click **"🔥 Auto-Inject Change"** (or use the interactive **Live Manual Tamper Editor** to type changes live for the professor).
2. Line 3 immediately mutates to: `Status: Approved [SIMULATED CHANGE]` highlighted in glowing red.
3. Modification progress leaps to **70%**.
4. The red modified SHA-256 hash appears next to the green original hash.

### Step 4: Minimize Attack Simulation & Observe Dashboard Alert
1. Click **"— Minimize to Dashboard"** (or **"← Minimize to Dashboard"** at the bottom).
2. The Attack Simulation collapses into the clean blue banner:
   * `⚔️ Attack Simulation Window is Minimized. FileGuard is actively monitoring endpoint integrity.`
3. **The Dashboard immediately catches the breach:**
   * **Audio Siren Alarm**: Plays high-frequency security alert.
   * **Top Red Alert Banner**: `⚠️ ALERT: File modification detected! The working copy of your file has been changed.`
   * **File Protection Card**: Turns red: `Compromised (Modification detected on disk)`.
   * **Status Badge**: Switches to `🔴 Threat Detected`.
   * **Protection Flow Stepper**: Step 3 lights up with a red alert badge (`! Detect Modification`).

### Step 5: Security Scan & Verified Recovery
1. Click **"🔍 Run Security Scan"**:
   * Inspect the exact hash divergence and Avalanche Effect percentage (~50% bit variance).
   * Review the **Batch Vault Audit** tab checking all documents in storage.
2. Click **"🔄 Restore Backup"**:
   * View the clean 3-line preview (expandable for full code).
   * Click **"🛡️ Execute Verified Backup Restoration"**.
   * FileGuard validates the backup's SHA-256 hash before restoring, overwrites the corrupted working copy, and restores system health.
3. Return to the Dashboard:
   * Status returns to `🟢 System Ready`.
   * File Protection resets to `🟢 Ready`.
   * All 5 steps in the Protection Flow are marked complete!

---

## 💡 6. Common Viva Questions & Answers

| Question | Recommended Answer |
| :--- | :--- |
| **Why use AES-GCM instead of AES-CBC?** | AES-CBC only provides confidentiality. If ciphertext is tampered with, CBC will not detect it without an external HMAC. AES-GCM is an AEAD cipher that provides both confidentiality and built-in tamper detection via a 16-byte authentication tag. |
| **What happens if an attacker tampers with the encrypted file?** | In AES-GCM, any bit flip in the ciphertext or tag causes decryption to fail immediately with an `InvalidTag` exception, preventing corrupted or malicious payload execution. |
| **Why not just hash the whole hard drive periodically?** | Cryptographic hashing consumes CPU and disk I/O. In enterprise environments, baseline hashes are maintained for critical system and configuration files, while heuristic and behavioral monitoring protects high-turnover user directories. |
| **Is a local backup sufficient protection against real ransomware?** | No. Real ransomware running with administrative privileges could overwrite local backup folders. In real-world enterprise deployments, backups must be **immutable (WORM)**, **air-gapped**, or pushed to an isolated off-site cloud vault. FileGuard simulates this separation via dedicated directories. |

---

## 🛡️ 7. Project Structure

```text
FileGuard/
├── app.py               # Main Streamlit Cyber Operations Dashboard
├── crypto_engine.py     # Decoupled AES-256-GCM & SHA-256 Cryptographic Engine
├── test_workflow.py     # Comprehensive 10-point Automated Unit & Workflow Test
├── requirements.txt     # Python Dependencies (streamlit, cryptography)
├── README.md            # Project Documentation & Viva Guide
└── data/
    ├── encryption.key   # 256-bit AES Master Key
    ├── metadata.json    # Registry of Filenames & Trusted SHA-256 Baselines
    ├── originals/       # Working Copy Directory
    ├── encrypted/       # AES-256-GCM Encrypted Vault Copies (.enc)
    └── backups/         # Isolated Trusted Baseline Backups
```
