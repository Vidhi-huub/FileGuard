"""
FileGuard — Ransomware-Resistant File Protection System
======================================================
College Cryptography Microproject
Designed to match the exact evaluation UI specification:
  - Clean Home / Dashboard with Upload Your File & Quick Actions (Matching Mockup Image 2)
  - Attack Simulation Window with Maximize / Split / Minimize controls inside the simulation window
  - Clean Home page without unnecessary minimized banners
  - Responsive, dynamic formatting in Side-by-Side view without text clipping
  - Siren alarm & floating Red Alert banner on unauthorized file modification
  - Team attribution: Vidhi Manani (TYIT1 - 5) & Riddhi Parmar (TYIT1 - 9)
"""

import datetime
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import streamlit as st
from cryptography.exceptions import InvalidTag

from crypto_engine import (
    ATTACK_SCENARIOS,
    DEMO_SAMPLE_TEXT,
    DEMO_TAMPERED_TEXT,
    SIMULATION_MARKER,
    calculate_avalanche_metrics,
    calculate_hash,
    decrypt_file,
    encrypt_file,
    generate_hash_diff_html,
    load_metadata,
    load_or_create_key,
    save_metadata,
    short_hash,
    simulate_attack_scenario,
)

# ============================================================
# 1. FILEGUARD STORAGE PATHS & CONSTANTS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ORIGINALS_DIR = DATA_DIR / "originals"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
BACKUPS_DIR = DATA_DIR / "backups"

KEY_FILE = DATA_DIR / "encryption.key"
METADATA_FILE = DATA_DIR / "metadata.json"

DEFAULT_DOC_NAME = "Project_Report.txt"


def ensure_storage_directories() -> None:
    """Ensure data and operational subdirectories exist safely."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for folder in (ORIGINALS_DIR, ENCRYPTED_DIR, BACKUPS_DIR):
        folder.mkdir(parents=True, exist_ok=True)


def render_html(html_code: str) -> None:
    """
    Renders raw HTML safely by stripping each line and joining with a space,
    preventing any markdown 4-space indentation code-block escaping bug.
    """
    cleaned = " ".join(line.strip() for line in html_code.splitlines() if line.strip())
    st.markdown(cleaned, unsafe_allow_html=True)


# ============================================================
# 2. AUDIO & AUDIT SYSTEM
# ============================================================

def trigger_audio_alarm() -> None:
    """Plays an authentic security breach alert tone using the Web Audio API."""
    render_html(
        """
        <script>
        (function() {
            try {
                var AudioContext = window.AudioContext || window.webkitAudioContext;
                if (!AudioContext) return;
                var ctx = new AudioContext();
                function playBeep(freq, start, duration) {
                    var osc = ctx.createOscillator();
                    var gain = ctx.createGain();
                    osc.type = 'sawtooth';
                    osc.frequency.setValueAtTime(freq, ctx.currentTime + start);
                    gain.gain.setValueAtTime(0.25, ctx.currentTime + start);
                    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + start + duration);
                    osc.connect(gain);
                    gain.connect(ctx.destination);
                    osc.start(ctx.currentTime + start);
                    osc.stop(ctx.currentTime + start + duration);
                }
                playBeep(880, 0, 0.18);
                playBeep(440, 0.22, 0.22);
                playBeep(980, 0.48, 0.3);
            } catch(e) {
                console.log("Audio alert error:", e);
            }
        })();
        </script>
        """
    )


def log_event(file_id: str, action: str, description: str, status: str = "INFO") -> None:
    """Record an audit trail event for a specific file with current timestamp."""
    if "audit_timeline" not in st.session_state:
        st.session_state["audit_timeline"] = {}
    if file_id not in st.session_state["audit_timeline"]:
        st.session_state["audit_timeline"][file_id] = []

    timestamp = datetime.datetime.now().strftime("%I:%M %p")
    st.session_state["audit_timeline"][file_id].append({
        "timestamp": timestamp,
        "action": action,
        "description": description,
        "status": status,
    })


def get_timeline(file_id: str) -> List[dict]:
    """Retrieve recorded timeline events for a given file ID."""
    return st.session_state.get("audit_timeline", {}).get(file_id, [])


# ============================================================
# 3. CSS DESIGN (DYNAMIC & RESPONSIVE)
# ============================================================

def inject_custom_css() -> None:
    """Injects high-fidelity dark navy theme matching the design mockup."""
    render_html(
        """
        <style>
        .stApp {
            background-color: #080f24 !important;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        section[data-testid="stSidebar"] {
            background-color: #060b1a !important;
            border-right: 1px solid #14203d !important;
        }

        .fg-brand-box {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 0 18px 0;
            border-bottom: 1px solid #14203d;
            margin-bottom: 16px;
        }
        .fg-brand-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #1d4ed8, #3b82f6);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.35rem;
            color: #ffffff;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
        }
        .fg-brand-title {
            font-size: 1.18rem;
            font-weight: 700;
            color: #ffffff;
            line-height: 1.1;
        }
        .fg-brand-subtitle {
            font-size: 0.72rem;
            color: #64748b;
            margin-top: 2px;
        }

        .fg-team-box {
            background: #0b1329;
            border: 1px solid #1c2b50;
            border-radius: 8px;
            padding: 12px 14px;
            margin-top: 26px;
        }
        .fg-team-title {
            font-size: 0.78rem;
            text-transform: uppercase;
            font-weight: 700;
            color: #94a3b8;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .fg-team-member {
            font-size: 0.82rem;
            color: #cbd5e1;
            line-height: 1.4;
        }

        .fg-main-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }
        .fg-main-title {
            font-size: 1.55rem;
            font-weight: 700;
            color: #ffffff;
            margin: 0;
            letter-spacing: -0.3px;
        }
        .fg-main-sub {
            font-size: 0.84rem;
            color: #94a3b8;
            margin-top: 3px;
        }
        .fg-pill-ready {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #34d399;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.76rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
        }
        .fg-pill-alert {
            background: rgba(239, 68, 68, 0.18);
            border: 1px solid #ef4444;
            color: #f87171;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.76rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
        }

        /* Responsive 3 Top Metric Cards */
        .fg-metric-grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        .fg-metric-card {
            background: #0e172e;
            border: 1px solid #19274a;
            border-radius: 10px;
            padding: 12px 14px;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
            height: 100%;
            min-width: 0;
            overflow: hidden;
        }
        .fg-metric-icon-wrap {
            width: 38px;
            height: 38px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            flex-shrink: 0;
        }
        .fg-icon-green { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .fg-icon-blue { background: rgba(37, 99, 235, 0.18); color: #38bdf8; }
        .fg-icon-purple { background: rgba(99, 102, 241, 0.18); color: #818cf8; }

        .fg-metric-label {
            font-size: 0.72rem;
            color: #94a3b8;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .fg-metric-val {
            font-size: 1.05rem;
            font-weight: 700;
            color: #ffffff;
            line-height: 1.2;
            margin: 1px 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .fg-metric-desc {
            font-size: 0.68rem;
            color: #64748b;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* Top Centered Red Alert Banner */
        .fg-top-alert-banner {
            background: linear-gradient(135deg, #381219 0%, #200d14 100%);
            border: 1.5px solid #ef4444;
            border-radius: 12px;
            padding: 12px 20px;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.35);
        }
        .fg-top-alert-content {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .fg-top-alert-icon {
            width: 38px;
            height: 38px;
            background: rgba(239, 68, 68, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: #f87171;
            flex-shrink: 0;
        }
        .fg-top-alert-badge {
            font-size: 0.7rem;
            text-transform: uppercase;
            font-weight: 800;
            color: #f87171;
            letter-spacing: 0.8px;
        }
        .fg-top-alert-title {
            font-size: 1.05rem;
            font-weight: 700;
            color: #ffffff;
            margin: 1px 0;
        }
        .fg-top-alert-desc {
            font-size: 0.8rem;
            color: #fca5a5;
        }

        /* Standard Card */
        .fg-card {
            background: #0e172e;
            border: 1px solid #19274a;
            border-radius: 10px;
            padding: 16px 18px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
            margin-bottom: 14px;
        }
        .fg-card-head {
            font-size: 0.98rem;
            font-weight: 600;
            color: #f8fafc;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        /* Protection Flow 5-Step Stepper */
        .fg-workflow-stepper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #14203d;
            gap: 4px;
            flex-wrap: nowrap;
            overflow-x: auto;
        }
        .fg-step-node {
            display: flex;
            align-items: center;
            gap: 5px;
            flex-shrink: 0;
        }
        .fg-step-circle {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.68rem;
            font-weight: 700;
            flex-shrink: 0;
        }
        .fg-step-circle.done { background: #10b981; color: #fff; }
        .fg-step-circle.alert { background: #ef4444; color: #fff; }
        .fg-step-circle.wait { background: #19274a; color: #94a3b8; border: 1px solid #28375a; }
        .fg-step-text {
            font-size: 0.72rem;
            font-weight: 600;
            color: #cbd5e1;
            white-space: nowrap;
        }
        .fg-step-line {
            flex: 1;
            min-width: 8px;
            height: 2px;
            background: #19274a;
            margin: 0 4px;
        }
        .fg-step-line.active { background: #10b981; }
        .fg-step-line.alert { background: #ef4444; }

        /* Attack Simulation Card Container */
        .fg-sim-panel {
            background: #091226;
            border: 1.5px solid #2563eb;
            border-radius: 12px;
            padding: 16px 18px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
            margin-bottom: 16px;
        }
        .fg-sim-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 4px;
        }
        .fg-sim-title {
            font-size: 1.18rem;
            font-weight: 800;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .fg-sim-sub {
            font-size: 0.78rem;
            color: #94a3b8;
            margin-bottom: 12px;
            line-height: 1.35;
        }
        .fg-sim-doc-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #0d172e;
            border: 1px solid #1c2b50;
            border-radius: 6px 6px 0 0;
            padding: 7px 12px;
            font-size: 0.78rem;
            color: #94a3b8;
        }
        .fg-sim-codebox {
            background: #060b18;
            border: 1px solid #1c2b50;
            border-top: none;
            border-radius: 0 0 6px 6px;
            padding: 8px 12px;
            font-family: "Consolas", monospace;
            font-size: 0.82rem;
            color: #cbd5e1;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .fg-sim-line {
            display: flex;
            gap: 10px;
        }
        .fg-sim-num {
            color: #64748b;
            user-select: none;
            min-width: 14px;
        }
        .fg-sim-line.highlight {
            background: rgba(239, 68, 68, 0.22);
            color: #fca5a5;
            border-radius: 3px;
            padding: 0 4px;
            font-weight: 600;
        }

        .fg-sim-hash-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 10px 0;
        }
        .fg-sim-hash-green {
            background: #06231a;
            border: 1px solid #10b981;
            border-radius: 6px;
            padding: 8px 10px;
            min-width: 0;
            overflow: hidden;
        }
        .fg-sim-hash-red {
            background: #230d12;
            border: 1px solid #ef4444;
            border-radius: 6px;
            padding: 8px 10px;
            min-width: 0;
            overflow: hidden;
        }

        /* Streamlit Button Customization - Prevents Ellipses Clipping */
        div.stButton > button {
            white-space: normal !important;
            word-break: normal !important;
            overflow-wrap: break-word !important;
            height: auto !important;
            min-height: 38px !important;
            padding: 6px 10px !important;
            font-size: 0.84rem !important;
            line-height: 1.25 !important;
            border-radius: 8px !important;
        }
        div.stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #ef4444, #dc2626) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            box-shadow: 0 4px 14px rgba(239, 68, 68, 0.3) !important;
        }
        div.stButton > button[kind="secondary"], div.stButton > button:not([kind="primary"]) {
            background-color: #0f1c38 !important;
            border: 1px solid #1f2f55 !important;
            color: #cbd5e1 !important;
            font-weight: 500 !important;
        }
        div.stButton > button:hover {
            border-color: #38bdf8 !important;
            color: #ffffff !important;
        }

        header[data-testid="stHeader"] { background: transparent; }
        .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
        </style>
        """
    )


# ============================================================
# 4. STORAGE & DEFAULT PROJECT FILE INITIALIZATION
# ============================================================

st.set_page_config(
    page_title="FileGuard — Ransomware-Resistant File Protection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_custom_css()
ensure_storage_directories()
KEY = load_or_create_key(KEY_FILE)
metadata = load_metadata(METADATA_FILE)

# Auto-initialize Project_Report.txt if missing
if "project_report_001" not in metadata:
    default_id = "project_report_001"
    default_bytes = DEMO_SAMPLE_TEXT.encode("utf-8")
    (ORIGINALS_DIR / default_id).write_bytes(default_bytes)
    shutil.copyfile(ORIGINALS_DIR / default_id, BACKUPS_DIR / default_id)
    (ENCRYPTED_DIR / f"{default_id}.enc").write_bytes(encrypt_file(default_bytes, KEY))

    baseline_h = calculate_hash(default_bytes)
    metadata[default_id] = {
        "filename": DEFAULT_DOC_NAME,
        "sha256": baseline_h,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_metadata(METADATA_FILE, metadata)

# Active file tracking
valid_file_ids = list(metadata.keys())
if "selected_file_id" not in st.session_state or st.session_state["selected_file_id"] not in valid_file_ids:
    st.session_state["selected_file_id"] = "project_report_001"

active_id = st.session_state["selected_file_id"]
active_record = metadata[active_id]
active_filename = active_record["filename"]
trusted_hash = active_record["sha256"]

working_file_path = ORIGINALS_DIR / active_id
backup_file_path = BACKUPS_DIR / active_id
encrypted_file_path = ENCRYPTED_DIR / f"{active_id}.enc"

current_bytes = working_file_path.read_bytes()
current_hash = calculate_hash(current_bytes)
is_modified = (current_hash != trusted_hash)


# ============================================================
# 5. SIDEBAR NAVIGATION & STATE MANAGEMENT
# ============================================================

if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "Dashboard"

# Attack Simulation Window State: "minimized" (default), "maximized", "split"
if "sim_window_mode" not in st.session_state:
    st.session_state["sim_window_mode"] = "minimized"

if "alert_dismissed" not in st.session_state:
    st.session_state["alert_dismissed"] = False

def navigate_to(page_name: str) -> None:
    st.session_state["nav_page"] = page_name
    st.rerun()

with st.sidebar:
    render_html(
        """
        <div class="fg-brand-box">
            <div class="fg-brand-icon">🛡️</div>
            <div>
                <div class="fg-brand-title">FileGuard</div>
                <div class="fg-brand-subtitle">Ransomware-Resistant<br>File Protection System</div>
            </div>
        </div>
        """
    )

    nav_options = [
        "🏠 Dashboard",
        "📁 File Protection",
        "⚔️ Attack Simulation",
        "🔍 Security Scan",
        "🔄 Recovery",
        "❓ How It Works",
    ]

    current_idx = 0
    for i, opt in enumerate(nav_options):
        if st.session_state["nav_page"] in opt:
            current_idx = i
            break

    selected_nav = st.radio(
        "Navigation",
        nav_options,
        index=current_idx,
        label_visibility="collapsed",
    )
    raw_nav_name = selected_nav.split(" ", 1)[1]

    if raw_nav_name == "Attack Simulation" and st.session_state["nav_page"] != "Attack Simulation":
        st.session_state["sim_window_mode"] = "split"
        st.session_state["nav_page"] = "Dashboard"
        st.rerun()
    elif raw_nav_name != st.session_state["nav_page"]:
        st.session_state["nav_page"] = raw_nav_name
        st.rerun()

    render_html(
        """
        <div class="fg-team-box">
            <div class="fg-team-title">👥 Team</div>
            <div class="fg-team-member"><b>Vidhi Manani</b> (TYIT1 - 5)</div>
            <div class="fg-team-member"><b>Riddhi Parmar</b> (TYIT1 - 9)</div>
        </div>
        """
    )

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
    render_html(
        """
        <div style="font-size: 0.72rem; color: #475569; display: flex; align-items: center; gap: 8px;">
            <span>🛡️</span>
            <span><b>FileGuard v1.0</b><br>Secure &bull; Encrypt &bull; Recover</span>
        </div>
        """
    )


# ============================================================
# 6. ATTACK SIMULATION COMPONENT (RENDERER)
# ============================================================

def render_attack_simulation_panel(is_split: bool = False) -> None:
    """Renders the Attack Simulation window with interactive tamper tools and view toggles."""
    render_html(
        """
        <div class="fg-sim-panel">
            <div class="fg-sim-header">
                <div class="fg-sim-title">
                    <span style="color: #38bdf8;">⚡</span>
                    <span>Attack Simulation</span>
                </div>
            </div>
            <div class="fg-sim-sub">
                This window lets you simulate an unauthorized modification of your file. Changes are made only to a working copy.
            </div>
        </div>
        """
    )

    # Top Window Control Bar (Minimize / Toggle Full-Split / Close)
    win_c1, win_c2, win_c3 = st.columns([1.1, 1.1, 0.8])
    with win_c1:
        if st.button("— Minimize", type="primary", use_container_width=True):
            st.session_state["sim_window_mode"] = "minimized"
            st.rerun()
    with win_c2:
        if is_split:
            if st.button("🗖 Full Screen", use_container_width=True):
                st.session_state["sim_window_mode"] = "maximized"
                st.rerun()
        else:
            if st.button("🗗 Side-by-Side", use_container_width=True):
                st.session_state["sim_window_mode"] = "split"
                st.rerun()
    with win_c3:
        if st.button("✕ Close", use_container_width=True):
            st.session_state["sim_window_mode"] = "minimized"
            st.rerun()

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # File representations: Stacked vertically in split view (fits beautifully!), side-by-side in full view
    mod_line_cls = "highlight" if is_modified else ""
    try:
        curr_text = working_file_path.read_text(encoding="utf-8", errors="ignore")
        lines = curr_text.splitlines()
        l1 = lines[0] if len(lines) > 0 else "Project Name: FileGuard"
        l2 = lines[1] if len(lines) > 1 else "Original marks: 80"
        l3 = lines[2] if len(lines) > 2 else "Status: Approved"
        if is_modified and "[SIMULATED" not in l3:
            l3 = f"{l3} [SIMULATED CHANGE]"
    except Exception:
        l1 = "Project Name: FileGuard"
        l2 = "Original marks: 80"
        l3 = "Status: Approved [SIMULATED CHANGE]" if is_modified else "Status: Approved"

    def orig_file_html() -> str:
        return f"""
        <div style="font-size: 0.8rem; font-weight: 700; color: #cbd5e1; margin-bottom: 4px;">
            1. 📄 Original File (Read Only)
        </div>
        <div class="fg-sim-doc-header">
            <span>📄 {active_filename} &bull; 0.1 KB</span>
            <span style="color: #38bdf8; font-weight: 600;">View</span>
        </div>
        <div class="fg-sim-codebox">
            <div class="fg-sim-line"><span class="fg-sim-num">1</span><span>Project Name: FileGuard</span></div>
            <div class="fg-sim-line"><span class="fg-sim-num">2</span><span>Original marks: 80</span></div>
            <div class="fg-sim-line"><span class="fg-sim-num">3</span><span>Status: Approved</span></div>
        </div>
        """

    def mod_file_html() -> str:
        return f"""
        <div style="font-size: 0.8rem; font-weight: 700; color: #cbd5e1; margin-bottom: 4px;">
            2. ✏️ Working Copy (Being Modified)
        </div>
        <div class="fg-sim-doc-header">
            <span>📄 {active_filename} &bull; 0.1 KB</span>
            <span style="color: {'#f87171' if is_modified else '#38bdf8'}; font-weight: 600;">View</span>
        </div>
        <div class="fg-sim-codebox">
            <div class="fg-sim-line"><span class="fg-sim-num">1</span><span>{l1}</span></div>
            <div class="fg-sim-line"><span class="fg-sim-num">2</span><span>{l2}</span></div>
            <div class="fg-sim-line {mod_line_cls}"><span class="fg-sim-num">3</span><span>{l3}</span></div>
        </div>
        """

    if is_split:
        # Stacked layout in side-by-side mode gives full horizontal space to each box
        render_html(orig_file_html())
        render_html(mod_file_html())
    else:
        # Side-by-side columns in full window mode
        col_orig, col_mod = st.columns(2)
        with col_orig:
            render_html(orig_file_html())
        with col_mod:
            render_html(mod_file_html())

    # Action Trigger Buttons
    s_btn1, s_btn2 = st.columns([1.2, 1.2])
    with s_btn1:
        if st.button("🔥 Auto-Inject Change", type="primary", use_container_width=True):
            working_file_path.write_bytes(DEMO_TAMPERED_TEXT.encode("utf-8"))
            st.session_state["alert_dismissed"] = False
            log_event(active_id, "Hacker Attack", "Injected [SIMULATED CHANGE] on disk.", "ALERT")
            trigger_audio_alarm()
            st.rerun()

    with s_btn2:
        if st.button("🔄 Reset Working Copy", use_container_width=True):
            clean_b = backup_file_path.read_bytes()
            working_file_path.write_bytes(clean_b)
            st.session_state["alert_dismissed"] = True
            log_event(active_id, "Reset", "Restored working copy to baseline.", "SUCCESS")
            st.rerun()

    # Optional Live Manual Tamper Editor (for viva demonstration to the professor)
    with st.expander("✏️ Live Manual Tamper / Hacker Editor (Interactive Demo for Viva)"):
        manual_edit_text = st.text_area(
            "Modify working copy content manually:",
            value=working_file_path.read_text(encoding="utf-8", errors="ignore"),
            height=90,
            key="hacker_manual_input",
        )
        if st.button("💾 Apply Manual Hacker Tamper", use_container_width=True):
            working_file_path.write_text(manual_edit_text, encoding="utf-8")
            st.session_state["alert_dismissed"] = False
            log_event(active_id, "Manual Tamper", "User manually altered working copy bytes.", "ALERT")
            trigger_audio_alarm()
            st.rerun()

    # Section 3: Modification Progress
    render_html(
        f"""
        <div style="margin-top: 12px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; color: #94a3b8; margin-bottom: 4px;">
                <span style="font-weight: 600;">3. Modification Progress</span>
                <span style="font-weight: 700;">{'70%' if is_modified else '0%'}</span>
            </div>
        </div>
        """
    )
    st.progress(70 if is_modified else 0)

    # Section 4: Hash Comparison
    recalc_h = calculate_hash(working_file_path.read_bytes())
    render_html(
        f"""
        <div style="margin-top: 12px;">
            <div style="font-size: 0.8rem; font-weight: 700; color: #cbd5e1; margin-bottom: 6px;">
                4. Hash Comparison
            </div>
            <div class="fg-sim-hash-row">
                <div class="fg-sim-hash-green">
                    <div style="font-size: 0.7rem; color: #34d399; font-weight: 700; text-transform: uppercase;">🟢 Original Hash</div>
                    <div style="font-family: monospace; color: #34d399; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{trusted_hash[:20]}...</div>
                </div>
                <div class="{'fg-sim-hash-red' if is_modified else 'fg-sim-hash-green'}">
                    <div style="font-size: 0.7rem; color: {'#f87171' if is_modified else '#34d399'}; font-weight: 700; text-transform: uppercase;">
                        {'🔴 Modified Hash' if is_modified else '🟢 Current (Clean)'}
                    </div>
                    <div style="font-family: monospace; color: {'#fca5a5' if is_modified else '#34d399'}; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{recalc_h[:20]}...</div>
                </div>
            </div>
            <div style="font-size: 0.74rem; color: #94a3b8; margin-top: 4px;">
                ℹ️ The encrypted file and trusted backup remain unchanged.
            </div>
        </div>
        """
    )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    if st.button("← Minimize to Dashboard", use_container_width=True):
        st.session_state["sim_window_mode"] = "minimized"
        st.rerun()


# ============================================================
# 7. DASHBOARD COMPONENT (RENDERER - DYNAMIC & CLEAN)
# ============================================================

def render_dashboard_content(is_split: bool = False) -> None:
    """Renders the Home/Dashboard matching Image 2 perfectly, without minimized banners."""
    # TOP RED ALERT BANNER (If file is modified & not dismissed)
    if is_modified and not st.session_state.get("alert_dismissed"):
        render_html(
            """
            <div class="fg-top-alert-banner">
                <div class="fg-top-alert-content">
                    <div class="fg-top-alert-icon">⚠️</div>
                    <div>
                        <div class="fg-top-alert-badge">ALERT</div>
                        <div class="fg-top-alert-title">File modification detected!</div>
                        <div class="fg-top-alert-desc">The working copy of your file has been changed.</div>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="color: #f87171; font-size: 1.15rem;" title="Audio Alarm Sounding">🔊</span>
                </div>
            </div>
            """
        )
        t_col1, _ = st.columns([1.2, 3.5])
        with t_col1:
            if st.button("✕ Dismiss Alert", use_container_width=True):
                st.session_state["alert_dismissed"] = True
                st.rerun()

    # Main Header
    status_ready_html = (
        '<span class="fg-pill-alert">🔴 Threat Detected</span>'
        if is_modified
        else '<span class="fg-pill-ready">🟢 System Ready</span>'
    )

    title_size = "1.35rem" if is_split else "1.6rem"
    render_html(
        f"""
        <div class="fg-main-header">
            <div>
                <div class="fg-main-title" style="font-size: {title_size};">Welcome to FileGuard</div>
                <div class="fg-main-sub">Protect your files with encryption, integrity checking and smart recovery.</div>
            </div>
            <div>
                {status_ready_html}
            </div>
        </div>
        """
    )

    # 3 Top Metric Cards
    stat_val = "Compromised" if is_modified else "Ready"
    stat_color = "#f87171" if is_modified else "#34d399"
    stat_desc = "Modification detected" if is_modified else "Upload and protect file"

    render_html(
        f"""
        <div class="fg-metric-grid-3">
            <div class="fg-metric-card">
                <div class="fg-metric-icon-wrap fg-icon-green">🛡️</div>
                <div style="min-width: 0; overflow: hidden;">
                    <div class="fg-metric-label">File Protection</div>
                    <div class="fg-metric-val" style="color: {stat_color};">{stat_val}</div>
                    <div class="fg-metric-desc">{stat_desc}</div>
                </div>
            </div>
            <div class="fg-metric-card">
                <div class="fg-metric-icon-wrap fg-icon-blue">🔒</div>
                <div style="min-width: 0; overflow: hidden;">
                    <div class="fg-metric-label">Encryption</div>
                    <div class="fg-metric-val">AES-256-GCM</div>
                    <div class="fg-metric-desc">Strong encryption</div>
                </div>
            </div>
            <div class="fg-metric-card">
                <div class="fg-metric-icon-wrap fg-icon-purple">#</div>
                <div style="min-width: 0; overflow: hidden;">
                    <div class="fg-metric-label">Integrity Check</div>
                    <div class="fg-metric-val">SHA-256</div>
                    <div class="fg-metric-desc">Fingerprint verified</div>
                </div>
            </div>
        </div>
        """
    )

    # Middle Row: Upload Your File (Left) vs Quick Actions (Right)
    col_ratio = [1.25, 1.0] if is_split else [1.6, 1.0]
    col_dash_l, col_dash_r = st.columns(col_ratio)

    with col_dash_l:
        # Upload Your File Card (Matching Image 2)
        render_html(
            """
            <div class="fg-card">
                <div class="fg-card-head">
                    <span>Upload Your File</span>
                    <span style="font-size: 0.74rem; color: #94a3b8;">Choose a file to protect with encryption</span>
                </div>
            </div>
            """
        )

        up_file_dash = st.file_uploader(
            "Choose a file to protect:",
            type=None,
            label_visibility="collapsed",
            help="Supports .txt, .pdf, .docx, .png, .jpg (Max 10MB)",
        )

        up_btn_c1, up_btn_c2 = st.columns([1, 1])
        with up_btn_c1:
            if st.button("🔐 Protect File", type="primary", use_container_width=True):
                if up_file_dash is not None:
                    new_id = uuid.uuid4().hex[:12]
                    raw_b = up_file_dash.getvalue()
                    (ORIGINALS_DIR / new_id).write_bytes(raw_b)
                    shutil.copyfile(ORIGINALS_DIR / new_id, BACKUPS_DIR / new_id)
                    (ENCRYPTED_DIR / f"{new_id}.enc").write_bytes(encrypt_file(raw_b, KEY))

                    b_hash = calculate_hash(raw_b)
                    metadata[new_id] = {
                        "filename": up_file_dash.name,
                        "sha256": b_hash,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    save_metadata(METADATA_FILE, metadata)
                    st.session_state["selected_file_id"] = new_id
                    st.success(f"✅ Protection established for {up_file_dash.name}!")
                    time.sleep(0.4)
                    st.rerun()
                else:
                    st.warning("⚠️ Choose a file first or click Quick Demo below.")

        with up_btn_c2:
            if st.button("📄 Quick Load Demo", use_container_width=True):
                st.session_state["selected_file_id"] = "project_report_001"
                st.rerun()

        # Display Selected Protected Document & 5-Step Stepper
        dot_status_html = (
            '<span style="color: #f87171; font-weight: 700; font-size: 0.78rem;">🔴 Modification detected</span>'
            if is_modified
            else '<span style="color: #34d399; font-weight: 700; font-size: 0.78rem;">🟢 No modifications</span>'
        )

        s1 = "done"
        s2 = "done" if is_modified else "wait"
        s3 = "alert" if is_modified else "wait"
        s4 = "wait"
        s5 = "wait"

        render_html(
            f"""
            <div style="background: #0d172e; border: 1px solid #1c2b50; border-radius: 8px; padding: 12px 14px; margin-top: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
                        <span style="font-size: 1.3rem;">📄</span>
                        <div style="min-width: 0;">
                            <div style="font-weight: 700; color: #ffffff; font-size: 0.92rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{active_filename}</div>
                            <div style="font-size: 0.72rem; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Size: {len(current_bytes)/1024:.1f} KB &bull; SHA-256: <span style="color: #38bdf8; font-family: monospace;">{trusted_hash[:14]}...</span></div>
                        </div>
                    </div>
                    <div style="flex-shrink: 0;">
                        {dot_status_html}
                    </div>
                </div>

                <div class="fg-workflow-stepper">
                    <div class="fg-step-node">
                        <div class="fg-step-circle {s1}">✔</div>
                        <div class="fg-step-text">1 Protect</div>
                    </div>
                    <div class="fg-step-line {'active' if is_modified else ''}"></div>
                    <div class="fg-step-node">
                        <div class="fg-step-circle {s2}">{'✔' if is_modified else '2'}</div>
                        <div class="fg-step-text">2 Attack</div>
                    </div>
                    <div class="fg-step-line {'alert' if is_modified else ''}"></div>
                    <div class="fg-step-node">
                        <div class="fg-step-circle {s3}">{'!' if is_modified else '3'}</div>
                        <div class="fg-step-text">3 Detect</div>
                    </div>
                    <div class="fg-step-line"></div>
                    <div class="fg-step-node">
                        <div class="fg-step-circle {s4}">4</div>
                        <div class="fg-step-text">4 Recover</div>
                    </div>
                    <div class="fg-step-line"></div>
                    <div class="fg-step-node">
                        <div class="fg-step-circle {s5}">5</div>
                        <div class="fg-step-text">5 Verify</div>
                    </div>
                </div>
            </div>
            """
        )

    with col_dash_r:
        # Quick Actions Card (Matching Image 2)
        render_html(
            """
            <div class="fg-card">
                <div class="fg-card-head">
                    <span>Quick Actions</span>
                </div>
            </div>
            """
        )

        # Quick Action 1: Run Attack Simulation
        if st.button("⚡ Run Attack Simulation", type="primary", use_container_width=True):
            st.session_state["sim_window_mode"] = "split"
            st.rerun()

        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)

        # Quick Action 2: Run Security Scan
        if st.button("🔍 Run Security Scan", use_container_width=True):
            navigate_to("Security Scan")

        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)

        # Quick Action 3: Restore Backup
        if st.button("🔄 Restore Backup", use_container_width=True):
            navigate_to("Recovery")


# ============================================================
# 8. PAGE ROUTING CONTROLLER
# ============================================================

if st.session_state["nav_page"] == "Dashboard":

    # Mode 1: Full-Width Attack Simulation Window
    if st.session_state.get("sim_window_mode") == "maximized":
        render_attack_simulation_panel(is_split=False)

    # Mode 2: Split View (Side-by-Side Dashboard & Simulation)
    elif st.session_state.get("sim_window_mode") == "split":
        c_left, c_right = st.columns([1.18, 1.0])
        with c_left:
            render_dashboard_content(is_split=True)
        with c_right:
            render_attack_simulation_panel(is_split=True)

    # Mode 3: Minimized / Closed (Matching Image 2 Pixel-Perfect, No Banner!)
    else:
        render_dashboard_content(is_split=False)


# ============================================================
# 9. PAGE: SECURITY SCAN
# ============================================================

elif st.session_state["nav_page"] == "Security Scan":
    st.markdown("### 🔍 Security Scan & Discrepancy Detection")
    st.caption("Audits real-time working copy SHA-256 fingerprint against the immutable trusted baseline.")

    tab_single, tab_batch = st.tabs(["🛡️ Active File Scan", "📁 Batch Vault Audit (All Files)"])

    with tab_single:
        recalc_h = calculate_hash(working_file_path.read_bytes())
        has_threat = (recalc_h != trusted_hash)

        if st.button("🛡️ Run Security Scan Now", type="primary"):
            if has_threat:
                trigger_audio_alarm()
                log_event(active_id, "Security Scan: Threat Detected", "Hash discrepancy observed.", "ALERT")
            else:
                log_event(active_id, "Security Scan: Passed", "File verified clean.", "SUCCESS")
            st.rerun()

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        if has_threat:
            render_html(
                f"""
                <div style="background: #230d12; border: 2px solid #ef4444; border-radius: 12px; padding: 22px 24px; max-width: 650px; margin: 0 auto;">
                    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 14px;">
                        <span style="font-size: 1.6rem; color: #f87171;">⚠️</span>
                        <div>
                            <div style="font-size: 0.74rem; text-transform: uppercase; font-weight: 800; color: #f87171; letter-spacing: 0.8px;">SECURITY ALERT</div>
                            <div style="font-size: 1.2rem; font-weight: 800; color: #fff;">File Modification Detected!</div>
                        </div>
                    </div>

                    <div style="margin-bottom: 10px;">
                        <div style="color: #94a3b8; font-size: 0.74rem;">Affected File</div>
                        <div style="font-weight: 700; color: #fff; font-size: 0.95rem;">{active_filename}</div>
                    </div>

                    <div style="margin-bottom: 10px;">
                        <div style="color: #94a3b8; font-size: 0.74rem;">Expected Hash (Trusted Baseline)</div>
                        <div style="font-family: monospace; color: #38bdf8; font-size: 0.82rem;">{trusted_hash}</div>
                    </div>

                    <div style="margin-bottom: 12px;">
                        <div style="color: #f87171; font-size: 0.74rem;">Current Hash (Modified on Disk)</div>
                        <div style="font-family: monospace; color: #fca5a5; font-size: 0.82rem;">{recalc_h}</div>
                    </div>

                    <div style="color: #f87171; font-weight: 700; font-size: 0.86rem; margin-bottom: 12px;">
                        🔴 File contents changed &bull; Cryptographic signature mismatch
                    </div>

                    <div style="background: #111b33; border: 1px solid #1f2f55; border-radius: 6px; padding: 8px 12px; font-size: 0.78rem; color: #94a3b8;">
                        This appears to be a simulated unauthorized modification. The encrypted file and backup are safe.
                    </div>
                </div>
                """
            )

            metrics = calculate_avalanche_metrics(trusted_hash, recalc_h)
            st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
            st.markdown(
                f"**Avalanche Effect Metrics:** `{metrics['bits_changed']}` / 256 bits flipped (`{metrics['bit_percentage']}%`) due to modification."
            )

            s_c1, s_c2 = st.columns(2)
            with s_c1:
                if st.button("🔄 Proceed to Restore Backup", type="primary", use_container_width=True):
                    navigate_to("Recovery")
            with s_c2:
                if st.button("🏠 Back to Dashboard", use_container_width=True):
                    navigate_to("Dashboard")

        else:
            render_html(
                """
                <div style="background: #063422; border: 1px solid #10b981; border-radius: 10px; text-align: center; padding: 22px; max-width: 650px; margin: 0 auto;">
                    <div style="font-size: 2rem; color: #10b981; margin-bottom: 6px;">🟢</div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: #fff;">INTEGRITY VERIFIED: NO MODIFICATION DETECTED</div>
                    <div style="font-size: 0.82rem; color: #cbd5e1; margin-top: 4px;">
                        The real-time working copy SHA-256 fingerprint matches the immutable baseline exactly.
                    </div>
                </div>
                """
            )

    with tab_batch:
        st.markdown("#### Vault Integrity Summary")
        table_rows = []
        for fid, rec in metadata.items():
            fpath = ORIGINALS_DIR / fid
            if fpath.exists():
                live_h = calculate_hash(fpath.read_bytes())
                pass_status = "🟢 Clean" if live_h == rec["sha256"] else "🔴 Modified"
            else:
                pass_status = "⚠️ Missing"
            table_rows.append({
                "Document Name": rec["filename"],
                "Expected SHA-256": f"{rec['sha256'][:16]}...",
                "Integrity Status": pass_status,
                "Protected Since": rec.get("timestamp", "N/A"),
            })
        st.dataframe(table_rows, use_container_width=True)


# ============================================================
# 10. PAGE: RECOVERY & RESTORATION
# ============================================================

elif st.session_state["nav_page"] == "Recovery":
    st.markdown("### 🔄 Restore Trusted Backup")
    st.caption("Verify the immutable backup before restoring the original file to disk.")

    if is_modified:
        st.warning(f"⚠️ Discrepancy detected in working copy of **{active_filename}**!")

        # User-friendly preview: show only first few lines by default, expandable for full content
        backup_bytes = backup_file_path.read_bytes()
        backup_text = backup_bytes.decode("utf-8", errors="ignore")
        preview_lines = "\n".join(backup_text.splitlines()[:3])

        st.markdown("**Backup File Preview (First 3 Lines):**")
        st.code(preview_lines, language="text")

        with st.expander("📄 View Full Decrypted File Content"):
            st.code(backup_text, language="text")

        if st.button("🛡️ Execute Verified Backup Restoration", type="primary"):
            if calculate_hash(backup_bytes) == trusted_hash:
                working_file_path.write_bytes(backup_bytes)
                st.session_state["alert_dismissed"] = True
                log_event(active_id, "Backup Restored", "Working copy restored to baseline.", "SUCCESS")
                st.success("✅ File successfully restored and verified with trusted SHA-256 fingerprint!")
                time.sleep(0.5)
                navigate_to("Dashboard")
            else:
                st.error("❌ Pre-restoration integrity check failed! Backup does not match trusted hash.")

    else:
        render_html(
            f"""
            <div style="background: #063422; border: 1px solid #10b981; border-radius: 10px; text-align: center; padding: 24px; max-width: 520px; margin: 0 auto;">
                <div style="font-size: 2.2rem; color: #10b981; margin-bottom: 8px;">✔</div>
                <div style="font-size: 1.25rem; font-weight: 800; color: #fff;">RECOVERY SUCCESSFUL / SYSTEM SECURE</div>
                <div style="font-size: 0.85rem; color: #a7f3d0; margin-top: 4px; margin-bottom: 14px;">The trusted file has been restored and verified.</div>
                <div style="font-family: monospace; color: #34d399; font-size: 0.84rem;">{trusted_hash[:26]}... 📋</div>
            </div>
            """
        )
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        if st.button("🏠 Return to Dashboard", use_container_width=True):
            navigate_to("Dashboard")


# ============================================================
# 11. PAGE: FILE PROTECTION VAULT
# ============================================================

elif st.session_state["nav_page"] == "File Protection":
    st.markdown("### 📁 File Protection & Storage Vault Manager")
    st.caption("Protect additional documents, compute immutable SHA-256 baselines, and inspect key vaults.")

    up_f = st.file_uploader("Upload custom document (.txt, .pdf, .docx):", type=None)
    if st.button("🔐 Protect Uploaded File", type="primary"):
        if up_f is not None:
            nid = uuid.uuid4().hex[:12]
            fbytes = up_f.getvalue()
            (ORIGINALS_DIR / nid).write_bytes(fbytes)
            shutil.copyfile(ORIGINALS_DIR / nid, BACKUPS_DIR / nid)
            (ENCRYPTED_DIR / f"{nid}.enc").write_bytes(encrypt_file(fbytes, KEY))

            metadata[nid] = {
                "filename": up_f.name,
                "sha256": calculate_hash(fbytes),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            save_metadata(METADATA_FILE, metadata)
            st.session_state["selected_file_id"] = nid
            st.success(f"✅ Added {up_f.name} to vault!")
            time.sleep(0.4)
            navigate_to("Dashboard")


# ============================================================
# 12. PAGE: HOW IT WORKS (EXAMINER VIVA REFERENCE)
# ============================================================

elif st.session_state["nav_page"] == "How It Works":
    st.markdown("### ❓ How FileGuard Works &mdash; Examiner Viva Reference")
    st.markdown(
        """
        #### 1. Why SHA-256 for Baseline Fingerprinting?
        * SHA-256 produces a unique 256-bit digest.
        * Due to the **Avalanche Effect**, altering even a single bit in the file flips ~50% of the output bits pseudo-randomly.
        * This allows instant, deterministic tamper detection without decrypting or comparing full files.

        #### 2. Why AES-256 in GCM Mode?
        * Legacy modes like CBC or ECB only provide confidentiality.
        * **Galois/Counter Mode (GCM)** is an Authenticated Encryption with Associated Data (AEAD) cipher.
        * It outputs a 16-byte (128-bit) authentication tag (`GMAC`). If an attacker flips a single bit in the ciphertext, decryption aborts with `InvalidTag`.

        #### 3. Why Isolate the Backup?
        * Real-world ransomware targets working copies on user endpoints.
        * By isolating the verified baseline in a separate directory (simulating an air-gapped / immutable WORM backup), the system guarantees deterministic, zero-data-loss restoration.
        """
    )
    if st.button("🏠 Back to Dashboard"):
        navigate_to("Dashboard")
