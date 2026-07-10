import os
import sys

# Ensure UTF-8 output on Windows terminals to prevent UnicodeEncodeErrors with rich/emojis
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import tempfile
import webbrowser
from flask import Flask, jsonify, request, render_template_string
from sentinel_scan.core.scanner import scan_directory, scan_file, scan_zip_file
from sentinel_scan.core.risk_engine import calculate_security_score, detect_duplicates, compare_snapshots
from sentinel_scan.remediation.ai_explainer import get_ai_explanation
from sentinel_scan.remediation.fixer import audit_gitignore, fix_gitignore, install_pre_commit_hook
from sentinel_scan.sources.github_source import clone_and_scan_github_repo
from sentinel_scan.core.rules import SECRET_RULES
from sentinel_scan.core.validator import verify_secret_status

app = Flask(__name__)

# Single-page beautiful HTML Dashboard template with premium Glassmorphism, Console Simulator, and Active Verification
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelScan Enterprise Dashboard</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Outfit', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        darkbg: '#0b0f19',
                        darkcard: '#131b2e',
                        accentpurple: '#8b5cf6',
                        accentpink: '#ec4899',
                    }
                }
            }
        }
    </script>
    <style>
        body {
            background-color: #0b0f19;
            font-family: 'Outfit', sans-serif;
        }
        .glass {
            background: rgba(19, 27, 46, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .glow-purple:hover {
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.4);
        }
        .terminal-log {
            animation: fadeIn 0.3s ease-out;
        }
        .animate-fadeIn {
            animation: fadeIn 0.2s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #0b0f19;
        }
        ::-webkit-scrollbar-thumb {
            background: #1e293b;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #334155;
        }
    </style>
</head>
<body class="text-slate-100 min-h-screen pb-12">
    <!-- Navbar -->
    <nav class="sticky top-0 z-50 glass border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="bg-gradient-to-tr from-accentpurple to-accentpink p-2.5 rounded-xl shadow-lg">
                <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
            </div>
            <div>
                <h1 class="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-200 to-accentpurple bg-clip-text text-transparent">SentinelScan</h1>
                <p class="text-xs text-slate-400 font-medium">Enterprise Security Dashboard</p>
            </div>
        </div>
        <div class="flex items-center gap-3">
            <!-- Custom Policy Controls Button -->
            <button onclick="toggleModal('modal-policy')" class="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-all flex items-center justify-center relative group" title="Custom Scanning Policy">
                <svg class="w-5 h-5 text-accentpurple" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
                </svg>
            </button>
            
            <!-- Remediation Center Button -->
            <button onclick="toggleModal('modal-remediation')" class="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-all flex items-center justify-center relative group" title="Remediation Center">
                <svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
            </button>
            
            <span class="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1.5 rounded-full font-semibold flex items-center gap-1.5 shadow-sm">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> Local Engine Active
            </span>
        </div>
    </nav>

    <!-- Main Container -->
    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-6 mt-8 space-y-8 pb-12">
        
        <!-- Top Section: Scan Config Card (Full Width) -->
        <div class="glass p-6 rounded-2xl shadow-xl">
            <h2 class="text-lg font-bold mb-4 flex items-center gap-2 border-b border-slate-800 pb-2">
                <svg class="w-5 h-5 text-accentpurple" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
                </svg> Configure Scope
            </h2>

            <!-- Tabs -->
            <div class="flex border-b border-slate-800 mb-6 bg-slate-900/50 p-1 rounded-xl">
                <button onclick="switchTab('local')" id="tab-local" class="flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all bg-accentpurple text-white">Local Path</button>
                <button onclick="switchTab('github')" id="tab-github" class="flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all text-slate-400 hover:text-white">Git Repo</button>
                <button onclick="switchTab('upload')" id="tab-upload" class="flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all text-slate-400 hover:text-white">Upload File</button>
            </div>

            <!-- Local Scan Form -->
            <form id="form-local" class="space-y-5" onsubmit="handleScan(event, 'local')">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-5 items-end">
                    <div class="md:col-span-2">
                        <label class="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Target Folder or File Path</label>
                        <input type="text" name="target_path" value="." class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-accentpurple text-slate-200 font-mono">
                    </div>
                    <div>
                        <button type="submit" class="w-full bg-gradient-to-r from-accentpurple to-accentpink hover:opacity-90 text-white font-bold py-3.5 px-4 rounded-xl shadow-lg shadow-accentpurple/20 transition-all flex items-center justify-center gap-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg> Start Local Scan
                        </button>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <input type="checkbox" name="scan_history" id="scan_history" checked class="w-4.5 h-4.5 accent-accentpurple bg-slate-900 rounded border-slate-800">
                    <label for="scan_history" class="text-sm text-slate-300 font-medium">Scan Full Git Commit History</label>
                </div>
            </form>

            <!-- Git Scan Form -->
            <form id="form-github" class="space-y-5 hidden" onsubmit="handleScan(event, 'github')">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Repository Clone URL (HTTPS or SSH)</label>
                        <input type="text" name="github_url" placeholder="https://github.com/user/repo.git or git@github.com:user/repo.git" class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-accentpurple text-slate-200">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Username (Optional for Private HTTPS Repos)</label>
                        <input type="text" name="git_username" placeholder="e.g. oauth2 or username" class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-accentpurple text-slate-200">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Access Token / Password (Optional for Private HTTPS Repos)</label>
                        <input type="password" name="github_token" placeholder="Token / Password / Key" class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-accentpurple text-slate-200">
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <input type="checkbox" name="scan_history_gh" id="scan_history_gh" checked class="w-4.5 h-4.5 accent-accentpurple bg-slate-900 rounded border-slate-800">
                    <label for="scan_history_gh" class="text-sm text-slate-300 font-medium">Scan Full Git Commit History</label>
                </div>
                <button type="submit" class="w-full bg-gradient-to-r from-accentpurple to-accentpink hover:opacity-90 text-white font-bold py-3.5 px-4 rounded-xl shadow-lg shadow-accentpurple/20 transition-all flex items-center justify-center gap-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path>
                    </svg> Clone & Scan Repository
                </button>
            </form>

            <!-- File Upload Scan Form -->
            <form id="form-upload" class="space-y-5 hidden" onsubmit="handleScan(event, 'upload')">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-5 items-center">
                    <div class="md:col-span-2">
                        <div class="border-2 border-dashed border-slate-800 hover:border-accentpurple rounded-2xl p-6 text-center transition-all cursor-pointer bg-slate-900/30 group" onclick="document.getElementById('file-input').click()">
                            <svg class="w-8 h-8 text-slate-500 group-hover:text-accentpurple mx-auto mb-2 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                            </svg>
                            <span class="text-sm text-slate-300 font-semibold group-hover:text-white block">Click to browse file</span>
                            <span class="text-xs text-slate-500 mt-1 block">Supports .py, .js, .zip, .pdf, .docx, .xlsx, .pptx, .odt, .rtf, .doc, etc.</span>
                            <input type="file" id="file-input" name="file" class="hidden" onchange="updateUploadLabel(this)">
                        </div>
                        <div id="file-name-display" class="mt-3 text-xs text-accentpurple font-mono font-bold text-center"></div>
                    </div>
                    <div>
                        <button type="submit" class="w-full bg-gradient-to-r from-accentpurple to-accentpink hover:opacity-90 text-white font-bold py-3.5 px-4 rounded-xl shadow-lg shadow-accentpurple/20 transition-all flex items-center justify-center gap-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg> Scan Uploaded File
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Middle Section: Console Logs & Status -->
        <div class="w-full space-y-8">
            <!-- Error Banner (Custom Alert) -->
            <div id="error-banner" class="hidden bg-red-500/10 border border-red-500/20 p-5 rounded-2xl flex items-start gap-4 shadow-lg">
                <div class="bg-red-500/20 p-2 rounded-lg text-red-400">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                </div>
                <div class="flex-1">
                    <h4 class="text-sm font-bold text-red-400 font-sans">Execution Error</h4>
                    <p id="error-message" class="text-xs text-slate-300 mt-1 leading-relaxed font-mono whitespace-pre-wrap"></p>
                    <div id="error-tips-container" class="mt-3"></div>
                    <button onclick="document.getElementById('error-banner').classList.add('hidden')" class="mt-4 bg-red-500/20 hover:bg-red-500/30 text-red-400 font-bold px-3 py-1.5 rounded-lg text-[10px] transition-all">
                        Dismiss
                    </button>
                </div>
            </div>
            
            <!-- Scan Status Overlay (Real-time logs style) -->
            <div id="scan-loading" class="hidden glass p-6 rounded-2xl flex flex-col min-h-[400px]">
                <div class="flex items-center gap-3 border-b border-slate-800 pb-3 mb-4">
                    <div class="w-4 h-4 border-2 border-slate-800 border-t-accentpurple rounded-full animate-spin"></div>
                    <h3 class="text-sm font-bold text-slate-300">Scanner Engine Console Activity</h3>
                </div>
                <!-- Interactive CLI console screen -->
                <div class="flex-1 bg-black/80 font-mono text-xs p-4 rounded-xl text-emerald-400 overflow-y-auto space-y-2 h-[320px]" id="cli-console">
                    <!-- Stream logs -->
                </div>
            </div>

            <!-- Welcome Screen (Before first scan) -->
            <div id="scan-welcome" class="glass p-12 rounded-2xl text-center flex flex-col items-center justify-center min-h-[380px]">
                <div class="bg-accentpurple/10 p-5 rounded-full text-accentpurple mb-4">
                    <svg class="w-14 h-14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                    </svg>
                </div>
                <h3 class="text-xl font-bold text-slate-200">Scope Scanner Ready</h3>
                <p class="text-sm text-slate-400 max-w-md mx-auto mt-2 leading-relaxed">Configure policy tolerances and select a target scope above to initiate credential evaluation.</p>
            </div>
        </div>

        <!-- Dashboard Content (After scan) -->
        <div id="scan-results" class="space-y-8 hidden">
                
                <!-- Security Card Overview & Charts -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <!-- Posture Card -->
                    <div class="glass p-6 rounded-2xl shadow-xl flex flex-col justify-between">
                        <div>
                            <h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider">Security Grade</h3>
                            <div class="flex items-baseline gap-4 mt-3">
                                <span id="res-grade" class="text-6xl font-extrabold bg-gradient-to-r from-red-500 to-orange-400 bg-clip-text text-transparent">F</span>
                                <div>
                                    <div id="res-status" class="text-lg font-bold text-red-500">CRITICAL LEAKS</div>
                                    <div class="text-xs text-slate-400 mt-0.5">Score: <span id="res-score" class="font-bold">0</span>/100</div>
                                </div>
                            </div>
                            <p class="text-xs text-slate-400 mt-4 leading-relaxed">A lower score indicates active credentials are exposed in plain text within files or git commit objects.</p>
                        </div>
                        <div class="mt-6 border-t border-slate-800/80 pt-4 flex justify-between text-xs font-semibold">
                            <span class="text-slate-400">Total Findings:</span>
                            <span id="res-total" class="text-slate-200 text-sm font-bold">40</span>
                        </div>
                    </div>

                    <!-- Chart Card -->
                    <div class="glass p-6 rounded-2xl shadow-xl flex flex-col items-center justify-center">
                        <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 self-start">Severity Distribution</h3>
                        <div class="w-full max-h-[160px] flex items-center justify-center">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Gitignore Audit Banner -->
                <div id="gitignore-warning" class="hidden bg-amber-500/10 border border-amber-500/20 p-5 rounded-2xl flex items-start gap-4">
                    <div class="bg-amber-500/20 p-2 rounded-lg text-amber-400">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                    </div>
                    <div class="flex-1">
                        <h4 class="text-sm font-bold text-amber-400">Unignored Sensitive Files Detected</h4>
                        <p class="text-xs text-slate-400 mt-1 leading-relaxed">The following sensitive files exist in the codebase but are not ignored in your `.gitignore` configuration:</p>
                        <ul id="gitignore-list" class="list-disc pl-5 mt-2 text-xs font-mono text-red-400 space-y-1"></ul>
                        <button onclick="runRemediation('fix-gitignore')" class="mt-4 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs transition-all shadow-md shadow-amber-500/10">
                            Append patterns to .gitignore
                        </button>
                    </div>
                </div>

                <!-- Findings Table List -->
                <div class="glass rounded-2xl shadow-xl overflow-hidden">
                    <div class="px-6 py-5 border-b border-slate-800 bg-slate-900/30 flex items-center justify-between">
                        <h3 class="text-md font-bold text-slate-200">Secrets Found</h3>
                        <div class="flex items-center gap-3">
                            <input type="text" id="finding-search" oninput="filterFindings()" placeholder="Search findings..." class="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-accentpurple text-slate-200">
                        </div>
                    </div>
                    
                    <div class="divide-y divide-slate-800/60 overflow-y-auto max-h-[500px]" id="findings-container">
                        <!-- Dynamic findings injected here -->
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Policy Modal -->
    <div id="modal-policy" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fadeIn">
        <div class="glass w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] border border-slate-800">
            <!-- Modal Header -->
            <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
                <h3 class="text-md font-bold flex items-center gap-2 text-slate-200">
                    <svg class="w-5 h-5 text-accentpurple" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg> Custom Policy Controls
                </h3>
                <button onclick="toggleModal('modal-policy')" class="text-slate-400 hover:text-white p-1 hover:bg-slate-800 rounded-lg transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <!-- Modal Body -->
            <div class="p-6 overflow-y-auto space-y-5">
                <!-- Entropy Threshold Range Slider -->
                <div>
                    <div class="flex justify-between text-xs font-bold text-slate-400 mb-2">
                        <span class="uppercase tracking-wider">Entropy Threshold</span>
                        <span id="entropy-val" class="text-accentpurple font-mono text-sm">4.5</span>
                    </div>
                    <input type="range" id="entropy-slider" min="3.0" max="7.0" step="0.1" value="4.5" oninput="document.getElementById('entropy-val').innerText = this.value" class="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-accentpurple">
                    <p class="text-[10px] text-slate-500 mt-1">Lower values find more custom secrets but increase false positives.</p>
                </div>

                <!-- Detector Categories Checkboxes -->
                <div class="space-y-2">
                    <span class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Enabled Detectors</span>
                    <div class="grid grid-cols-2 gap-2 text-xs font-medium" id="policy-categories">
                        <!-- Loaded dynamically -->
                    </div>
                </div>
            </div>
            <!-- Modal Footer -->
            <div class="px-6 py-4 border-t border-slate-800 flex justify-end bg-slate-900/20">
                <button onclick="toggleModal('modal-policy')" class="bg-accentpurple hover:opacity-90 text-white font-bold py-2 px-5 rounded-xl text-xs shadow-lg shadow-accentpurple/15 transition-all">
                    Apply Policy
                </button>
            </div>
        </div>
    </div>

    <!-- Remediation Modal -->
    <div id="modal-remediation" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fadeIn">
        <div class="glass w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] border border-slate-800">
            <!-- Modal Header -->
            <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
                <h3 class="text-md font-bold flex items-center gap-2 text-slate-200">
                    <svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg> Remediation Center
                </h3>
                <button onclick="toggleModal('modal-remediation')" class="text-slate-400 hover:text-white p-1 hover:bg-slate-800 rounded-lg transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <!-- Modal Body -->
            <div class="p-6 overflow-y-auto space-y-4">
                <div class="bg-slate-900/50 p-4 rounded-xl border border-slate-800 space-y-3">
                    <h3 class="text-sm font-bold text-slate-300">Workspace Guards</h3>
                    <p class="text-xs text-slate-400 leading-relaxed">Block exposures at the pre-commit layer or automatically ignore exposed environment files.</p>
                    <div class="grid grid-cols-1 gap-2 pt-2">
                        <button onclick="runRemediation('install-hook')" class="w-full text-left bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold px-4 py-2.5 rounded-lg text-xs flex items-center justify-between transition-all">
                            <span>Install Git Pre-Commit Hook</span>
                            <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                        </button>
                        <button onclick="runRemediation('fix-gitignore')" class="w-full text-left bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold px-4 py-2.5 rounded-lg text-xs flex items-center justify-between transition-all">
                            <span>Audit & Auto-fix .gitignore</span>
                            <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                        </button>
                    </div>
                </div>
            </div>
            <!-- Modal Footer -->
            <div class="px-6 py-4 border-t border-slate-800 flex justify-end bg-slate-900/20">
                <button onclick="toggleModal('modal-remediation')" class="bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-bold py-2 px-5 rounded-xl text-xs border border-slate-700 transition-all">
                    Close
                </button>
            </div>
        </div>
    </div>

    <!-- JS Logic -->
    <script>
        let currentFindings = [];
        let severityChart = null;
        let rulesList = [];

        function toggleModal(id) {
            const modal = document.getElementById(id);
            if (modal.classList.contains('hidden')) {
                modal.classList.remove('hidden');
                modal.classList.add('flex');
            } else {
                modal.classList.remove('flex');
                modal.classList.add('hidden');
            }
        }

        // Close modal when clicking outside the dialog content
        window.addEventListener('click', (e) => {
            if (e.target.id && e.target.id.startsWith('modal-')) {
                toggleModal(e.target.id);
            }
        });

        // Fetch Rule categories on startup to populate Policy panel
        window.addEventListener('DOMContentLoaded', async () => {
            try {
                const response = await fetch('/api/rules');
                const rules = await response.json();
                rulesList = rules;
                
                const container = document.getElementById('policy-categories');
                container.innerHTML = '';
                
                // Get unique categories
                const categories = [...new Set(rules.map(r => r.category))];
                categories.forEach(cat => {
                    const label = document.createElement('label');
                    label.className = 'flex items-center gap-2 cursor-pointer p-1.5 hover:bg-slate-800/40 rounded-lg transition-colors';
                    label.innerHTML = `
                        <input type="checkbox" value="${cat}" checked class="accent-accentpurple rounded border-slate-800 bg-slate-900 select-category">
                        <span class="text-slate-300 font-medium truncate">${cat}</span>
                    `;
                    container.appendChild(label);
                });
            } catch (e) {
                console.error("Failed to load rules", e);
            }
        });

        function switchTab(tab) {
            document.getElementById('form-local').classList.add('hidden');
            document.getElementById('form-github').classList.add('hidden');
            document.getElementById('form-upload').classList.add('hidden');

            document.getElementById('tab-local').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all text-slate-400 hover:text-white';
            document.getElementById('tab-github').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all text-slate-400 hover:text-white';
            document.getElementById('tab-upload').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold transition-all text-slate-400 hover:text-white';

            if (tab === 'local') {
                document.getElementById('form-local').classList.remove('hidden');
                document.getElementById('tab-local').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold bg-accentpurple text-white';
            } else if (tab === 'github') {
                document.getElementById('form-github').classList.remove('hidden');
                document.getElementById('tab-github').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold bg-accentpurple text-white';
            } else if (tab === 'upload') {
                document.getElementById('form-upload').classList.remove('hidden');
                document.getElementById('tab-upload').className = 'flex-1 text-center py-2.5 rounded-lg text-sm font-semibold bg-accentpurple text-white';
            }
        }

        function updateUploadLabel(input) {
            if (input.files && input.files.length > 0) {
                document.getElementById('file-name-display').innerText = "Selected: " + input.files[0].name;
            }
        }

        function appendConsoleLog(message, type = 'info') {
            const consoleBox = document.getElementById('cli-console');
            const p = document.createElement('div');
            p.className = 'terminal-log';
            const timestamp = new Date().toLocaleTimeString();
            
            if (type === 'error') {
                p.innerHTML = `<span class="text-slate-500">[${timestamp}]</span> <span class="text-red-500 font-bold">● ERROR:</span> ${message}`;
            } else if (type === 'warn') {
                p.innerHTML = `<span class="text-slate-500">[${timestamp}]</span> <span class="text-amber-500 font-bold">▲ WARN:</span> ${message}`;
            } else if (type === 'success') {
                p.innerHTML = `<span class="text-slate-500">[${timestamp}]</span> <span class="text-emerald-400 font-bold">✔ SUCCESS:</span> ${message}`;
            } else {
                p.innerHTML = `<span class="text-slate-500">[${timestamp}]</span> <span class="text-cyan-400">ℹ INFO:</span> ${message}`;
            }
            consoleBox.appendChild(p);
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }

        function showError(message) {
            const banner = document.getElementById('error-banner');
            const msgElem = document.getElementById('error-message');
            const tipsContainer = document.getElementById('error-tips-container');
            
            banner.classList.remove('hidden');
            msgElem.innerText = message;
            
            // Clean up old tips
            tipsContainer.innerHTML = '';
            
            const msgLower = message.toLowerCase();
            let tips = [];
            
            if (msgLower.includes("repository not found") || msgLower.includes("not found")) {
                tips = [
                    "Verify the Git repository URL is spelled correctly.",
                    "If the repository is private, make sure you enter a valid Username and Access Token / Password.",
                    "Confirm the repository isn't deleted and can be loaded in a browser."
                ];
            } else if (msgLower.includes("authentication failed")) {
                tips = [
                    "Double-check your credentials (username and access token/password).",
                    "If using GitHub/GitLab, verify that your Personal Access Token has 'repo' (clone/read) scope.",
                    "Note: Standard account passwords may be rejected by GitHub; use an Access Token instead."
                ];
            } else if (msgLower.includes("could not connect") || msgLower.includes("resolve host")) {
                tips = [
                    "Verify your internet connection is active.",
                    "Check if a local proxy or firewall is blocking outbound Git requests.",
                    "Ensure the remote host (e.g. github.com) is currently online."
                ];
            } else if (msgLower.includes("permission denied")) {
                tips = [
                    "Ensure the Flask application has read permissions for the target folder/file.",
                    "Check if the file is locked or currently open in another program."
                ];
            } else if (msgLower.includes("not a valid zip") || msgLower.includes("corrupted")) {
                tips = [
                    "Check if the ZIP file was fully uploaded.",
                    "Verify the ZIP archive is not corrupted or password-protected by extracting it locally."
                ];
            } else if (msgLower.includes("path") && msgLower.includes("does not exist")) {
                tips = [
                    "Double-check the input path for spelling errors.",
                    "Remember that relative paths are evaluated from the SentinelScan repository root."
                ];
            }
            
            if (tips.length > 0) {
                const header = document.createElement('div');
                header.className = 'mt-3 text-xs font-bold text-red-400 uppercase tracking-wider';
                header.innerText = "Suggested Fixes:";
                tipsContainer.appendChild(header);
                
                const ul = document.createElement('ul');
                ul.className = 'list-disc pl-5 mt-1.5 text-xs text-slate-300 space-y-1';
                tips.forEach(tip => {
                    const li = document.createElement('li');
                    li.innerText = tip;
                    ul.appendChild(li);
                });
                tipsContainer.appendChild(ul);
            }
            
            banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        async function handleScan(event, type) {
            event.preventDefault();
            
            // Dismiss previous error banners
            document.getElementById('error-banner').classList.add('hidden');
            
            document.getElementById('scan-welcome').classList.add('hidden');
            document.getElementById('scan-results').classList.add('hidden');
            document.getElementById('scan-loading').classList.remove('hidden');

            const consoleBox = document.getElementById('cli-console');
            consoleBox.innerHTML = ''; // Reset console

            appendConsoleLog("Initializing SentinelScan structural search engine...");
            
            // Get custom policies
            const entropyVal = parseFloat(document.getElementById('entropy-slider').value);
            
            // Determine disabled rules
            const checkedCats = Array.from(document.querySelectorAll('.select-category:checked')).map(el => el.value);
            const disabledRules = rulesList
                .filter(r => !checkedCats.includes(r.category))
                .map(r => r.rule_id);

            if (disabledRules.length > 0) {
                appendConsoleLog(`Excluding ${disabledRules.length} scanning signatures based on policy overrides.`);
            }

            const formData = new FormData();
            formData.append('entropy_threshold', entropyVal);
            formData.append('disabled_rules', JSON.stringify(disabledRules));

            let url = '/api/scan';

            if (type === 'local') {
                const target = event.target.target_path.value;
                formData.append('target_path', target);
                formData.append('scan_history', event.target.scan_history.checked);
                appendConsoleLog(`Initiating scan on path: '${target}' (History: ${event.target.scan_history.checked})...`);
            } else if (type === 'github') {
                const urlVal = event.target.github_url.value;
                formData.append('github_url', urlVal);
                formData.append('github_token', event.target.github_token.value);
                formData.append('git_username', event.target.git_username.value);
                formData.append('scan_history', event.target.scan_history_gh.checked);
                appendConsoleLog(`Preparing git clone runner for URL: ${urlVal}...`);
            } else if (type === 'upload') {
                url = '/api/upload';
                const fileInput = document.getElementById('file-input');
                if (fileInput.files.length === 0) {
                    showError('Please select a file to scan.');
                    document.getElementById('scan-loading').classList.add('hidden');
                    document.getElementById('scan-welcome').classList.remove('hidden');
                    return;
                }
                formData.append('file', fileInput.files[0]);
                appendConsoleLog(`Uploading asset file: ${fileInput.files[0].name} for scanning...`);
            }

            // Simulate progress logs for premium UX feel
            setTimeout(() => appendConsoleLog("Evaluating text matching regex signature matrices...", 'info'), 500);
            setTimeout(() => appendConsoleLog(`Running Shannon Entropy evaluation (Threshold: ${entropyVal})...`, 'info'), 1100);
            setTimeout(() => appendConsoleLog("Scanning directory exclusions & parsing gitignore constraints...", 'info'), 1700);

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    body: formData
                });
                
                let data;
                try {
                    data = await response.json();
                } catch (jsonErr) {
                    throw new Error(`Server returned status ${response.status} (Failed to parse JSON response)`);
                }
                
                if (data.error) {
                    appendConsoleLog(data.error, 'error');
                    showError(data.error);
                    document.getElementById('scan-loading').classList.add('hidden');
                    document.getElementById('scan-welcome').classList.remove('hidden');
                    return;
                }

                appendConsoleLog(`Parsing completed. Detected ${data.findings.length} findings in target.`, 'success');
                
                setTimeout(() => {
                    document.getElementById('scan-loading').classList.add('hidden');
                    document.getElementById('scan-results').classList.remove('hidden');
                    currentFindings = data.findings;
                    displayResults(data);
                }, 2200);

            } catch (err) {
                console.error(err);
                appendConsoleLog(err.message || 'Scan connection failed.', 'error');
                showError(err.message || 'Scan connection failed. Check your network or Flask server status.');
                document.getElementById('scan-loading').classList.add('hidden');
                document.getElementById('scan-welcome').classList.remove('hidden');
            }
        }

        function displayResults(data) {
            // Render Stats
            document.getElementById('res-grade').innerText = data.risk_summary.grade;
            document.getElementById('res-status').innerText = data.risk_summary.status;
            document.getElementById('res-score').innerText = data.risk_summary.security_score;
            document.getElementById('res-total').innerText = data.risk_summary.counts.TOTAL;

            // Handle Gitignore warning banner
            const gitignoreWarn = document.getElementById('gitignore-warning');
            const gitignoreList = document.getElementById('gitignore-list');
            gitignoreList.innerHTML = '';
            
            if (data.gitignore_unignored && data.gitignore_unignored.length > 0) {
                gitignoreWarn.classList.remove('hidden');
                data.gitignore_unignored.forEach(file => {
                    const li = document.createElement('li');
                    li.innerText = file;
                    gitignoreList.appendChild(li);
                });
            } else {
                gitignoreWarn.classList.add('hidden');
            }

            // Populate Findings list
            renderFindingsList(data.findings);

            // Render Chart
            renderChart(data.risk_summary.counts);
        }

        function renderFindingsList(findings) {
            const container = document.getElementById('findings-container');
            container.innerHTML = '';

            if (findings.length === 0) {
                container.innerHTML = `
                    <div class="p-8 text-center text-slate-500 font-semibold">
                        🎉 No secrets found in this target!
                    </div>
                `;
                return;
            }

            findings.forEach((f, idx) => {
                const div = document.createElement('div');
                div.className = 'p-5 hover:bg-slate-900/40 transition-all flex flex-col gap-3 finding-item';
                div.setAttribute('data-search', `${f.rule_name} ${f.file_path} ${f.severity}`.toLowerCase());

                const severityColors = {
                    'CRITICAL': 'bg-red-500/10 text-red-400 border-red-500/20',
                    'HIGH': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
                    'MEDIUM': 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
                    'LOW': 'bg-green-500/10 text-green-400 border-green-500/20'
                };

                const badge = severityColors[f.severity] || 'bg-slate-500/10 text-slate-400';
                const sourceBadge = f.in_history ? 'Commit History' : 'Active File';
                const sourceColor = f.in_history ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20';

                div.innerHTML = `
                    <div class="flex items-start justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-2.5">
                                <h4 class="font-bold text-slate-200 text-sm">${f.rule_name}</h4>
                                <span class="text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider ${badge}">${f.severity}</span>
                                <span class="text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider ${sourceColor}">${sourceBadge}</span>
                                
                                <!-- Active status badge placeholder (Wow Factor 3) -->
                                <span id="verify-badge-${idx}" class="text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-slate-900 text-slate-400 border-slate-800 flex items-center gap-1">
                                    <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span> Unverified
                                </span>
                            </div>
                            <p class="text-xs font-mono text-slate-400 mt-1.5">${f.file_path}:${f.line_number}:${f.start_column}</p>
                        </div>
                        <div class="flex items-center gap-2">
                            <!-- Verify button -->
                            <button onclick="verifyKey(${idx})" class="text-xs bg-slate-900 hover:bg-slate-800 border border-slate-800 px-3 py-1.5 rounded-lg font-semibold text-slate-300 hover:text-white flex items-center gap-1.5 transition-all">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg> Verify Key
                            </button>
                            <button onclick="toggleDetails(${idx})" class="text-slate-400 hover:text-white transition-colors bg-slate-800/40 p-1.5 rounded-lg border border-slate-800">
                                <svg id="arrow-${idx}" class="w-4 h-4 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <!-- Collapsible Section -->
                    <div id="details-${idx}" class="hidden mt-3 space-y-4 pt-3 border-t border-slate-800/50">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <span class="text-[10px] uppercase font-bold tracking-wider text-slate-500">Masked Secret Value</span>
                                <div class="bg-slate-900 px-3 py-2.5 rounded-lg border border-slate-800 font-mono text-xs text-red-400 mt-1 select-all">${maskSecretVal(f.secret)}</div>
                            </div>
                            <div>
                                <span class="text-[10px] uppercase font-bold tracking-wider text-slate-500">Security Description</span>
                                <p class="text-xs text-slate-400 mt-1 leading-relaxed">${f.description}</p>
                            </div>
                        </div>

                        ${f.line_content ? `
                        <div>
                            <span class="text-[10px] uppercase font-bold tracking-wider text-slate-500">Exposed Code Context</span>
                            <pre class="bg-slate-950/80 px-4 py-3 rounded-lg border border-slate-800/60 font-mono text-xs text-slate-300 mt-1 overflow-x-auto whitespace-pre-wrap"><code>${escapeHTML(f.line_content)}</code></pre>
                        </div>
                        ` : ''}

                        <!-- AI Remediation Request Button -->
                        <div class="flex items-center gap-3">
                            <button onclick="requestAiRemediation(${idx})" class="bg-accentpurple/10 border border-accentpurple/30 text-accentpurple hover:bg-accentpurple/20 font-bold px-4 py-2 rounded-lg text-xs transition-all flex items-center gap-1.5">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                                </svg> Get Remediation Strategy
                            </button>
                            <div id="ai-loading-${idx}" class="hidden w-4 h-4 border-2 border-slate-700 border-t-accentpurple rounded-full animate-spin"></div>
                        </div>

                        <!-- AI Panel result -->
                        <div id="ai-remediation-${idx}" class="hidden bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
                            <div class="flex items-center justify-between">
                                <span id="ai-provider-${idx}" class="text-[10px] font-bold text-accentpurple uppercase tracking-wider">AI RECOMMENDATIONS</span>
                                <span class="text-[10px] text-slate-500">Click to collapse</span>
                            </div>
                            <p id="ai-text-${idx}" class="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans"></p>
                        </div>
                    </div>
                `;
                container.appendChild(div);
            });
        }

        async function verifyKey(idx) {
            const finding = currentFindings[idx];
            const badge = document.getElementById(`verify-badge-${idx}`);
            
            badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse"></span> Verifying...`;
            badge.className = 'text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-yellow-500/10 text-yellow-400 border-yellow-500/20 flex items-center gap-1';

            try {
                const response = await fetch('/api/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ rule_id: finding.rule_id, secret: finding.secret })
                });
                const result = await response.json();
                
                if (result.status === 'active') {
                    badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping"></span> Live & Active`;
                    badge.className = 'text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-red-500/20 text-red-400 border-red-500/30 flex items-center gap-1';
                } else if (result.status === 'inactive') {
                    badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Inactive / Expired`;
                    badge.className = 'text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border-emerald-500/20 flex items-center gap-1';
                } else {
                    badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span> Offline / Unverified`;
                    badge.className = 'text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-slate-900 text-slate-400 border-slate-800 flex items-center gap-1';
                }
                
                // Show notification tooltip message on hovering badge
                badge.title = result.message;
            } catch (err) {
                console.error(err);
                badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span> Unverified`;
                badge.className = 'text-[10px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider bg-slate-900 text-slate-400 border-slate-800 flex items-center gap-1';
            }
        }

        function filterFindings() {
            const query = document.getElementById('finding-search').value.toLowerCase();
            const items = document.querySelectorAll('.finding-item');
            items.forEach(item => {
                const searchTxt = item.getAttribute('data-search');
                if (searchTxt.includes(query)) {
                    item.classList.remove('hidden');
                } else {
                    item.classList.add('hidden');
                }
            });
        }

        function toggleDetails(idx) {
            const panel = document.getElementById(`details-${idx}`);
            const arrow = document.getElementById(`arrow-${idx}`);
            panel.classList.toggle('hidden');
            arrow.classList.toggle('rotate-180');
        }

        async function requestAiRemediation(idx) {
            const finding = currentFindings[idx];
            const loading = document.getElementById(`ai-loading-${idx}`);
            const panel = document.getElementById(`ai-remediation-${idx}`);
            const textElem = document.getElementById(`ai-text-${idx}`);
            const providerElem = document.getElementById(`ai-provider-${idx}`);

            loading.classList.remove('hidden');

            try {
                const response = await fetch('/api/explain', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ finding: finding })
                });
                const data = await response.json();
                
                loading.classList.add('hidden');
                panel.classList.remove('hidden');

                providerElem.innerText = `Remediation advice source: ${data.provider}`;
                textElem.innerText = data.explanation;
            } catch (err) {
                console.error(err);
                loading.classList.add('hidden');
                alert('AI remediation request failed.');
            }
        }

        function renderChart(counts) {
            const ctx = document.getElementById('severityChart').getContext('2d');
            
            if (severityChart) {
                severityChart.destroy();
            }

            const total = counts.TOTAL || 0;
            const data = total === 0 ? [1] : [
                counts.CRITICAL || 0,
                counts.HIGH || 0,
                counts.MEDIUM || 0,
                counts.LOW || 0
            ];
            const backgroundColor = total === 0 ? ['#10b981'] : ['#ef4444', '#f59e0b', '#eab308', '#10b981'];
            const labels = total === 0 ? ['Secure'] : ['Critical', 'High', 'Medium', 'Low'];

            severityChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: backgroundColor,
                        borderColor: '#0b0f19',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#94a3b8',
                                font: {
                                    family: 'Outfit',
                                    size: 11
                                }
                            }
                        }
                    },
                    cutout: '65%'
                }
            });
        }

        async function runRemediation(type) {
            let url = '';
            if (type === 'install-hook') url = '/api/install-hook';
            else if (type === 'fix-gitignore') url = '/api/fix/gitignore';

            try {
                const response = await fetch(url, { method: 'POST' });
                const data = await response.json();
                alert(data.message);
                
                // Refresh if gitignore fix
                if (type === 'fix-gitignore') {
                    document.getElementById('form-local').dispatchEvent(new Event('submit'));
                }
            } catch (e) {
                alert('Remediation request failed.');
            }
        }

        // Helper string mask
        function maskSecretVal(secret) {
            if (secret.length <= 8) return '********';
            return secret.substring(0, 4) + '****************' + secret.substring(secret.length - 4);
        }

        function escapeHTML(str) {
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    </script>
</body>
</html>
"""

def make_error_user_friendly(e: Exception) -> str:
    """Translates common backend exceptions into clean, helpful, user-friendly messages."""
    msg = str(e)
    import zipfile
    if isinstance(e, zipfile.BadZipFile) or "is not a zip file" in msg.lower():
        return "The uploaded file is not a valid ZIP archive or is corrupted. Please verify the archive format and try again."
    elif isinstance(e, PermissionError) or "permission denied" in msg.lower():
        return "Permission denied. The system does not have permission to read the specified target path or directory."
    elif isinstance(e, FileNotFoundError) or "does not exist" in msg.lower():
        return "File or directory not found. Please verify that the path is correct and exists on disk."
    
    # Git cloning error messages are already translated in github_source.py
    if "failed to clone repository" in msg.lower():
        return msg
        
    return f"An unexpected error occurred during scanning: {msg}"

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/rules", methods=["GET"])
def get_rules():
    rules_data = []
    for r in SECRET_RULES:
        rules_data.append({
            "rule_id": r.rule_id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity
        })
    return jsonify(rules_data)

@app.route("/api/verify", methods=["POST"])
def verify_finding():
    data = request.json or {}
    rule_id = data.get("rule_id", "")
    secret = data.get("secret", "")
    
    result = verify_secret_status(rule_id, secret)
    return jsonify(result)

@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        target_path = request.form.get("target_path", ".")
        scan_history = request.form.get("scan_history") == "true"
        github_url = request.form.get("github_url")
        github_token = request.form.get("github_token")
        git_username = request.form.get("git_username")

        # Sanitize placeholders like "ghp_***" or empty strings to None
        if github_token and (github_token.startswith("ghp_***") or github_token.strip() == ""):
            github_token = None
            
        if git_username and git_username.strip() == "":
            git_username = None

        entropy_threshold = float(request.form.get("entropy_threshold", 4.5) or 4.5)
        import json
        disabled_rules_raw = request.form.get("disabled_rules")
        disabled_rules = json.loads(disabled_rules_raw) if disabled_rules_raw else []

        config = {
            "entropy_threshold": entropy_threshold,
            "disabled_rules": disabled_rules
        }

        findings = []
        gitignore_unignored = []
        
        if github_url:
            # Remote Git Scan (temporarily clones and scans)
            findings = clone_and_scan_github_repo(
                github_url, 
                github_token=github_token, 
                scan_history=scan_history,
                git_username=git_username
            )
            # Filter findings based on disabled rules
            findings = [f for f in findings if f.get("rule_id") not in disabled_rules]
        else:
            # Local Scan
            if not os.path.exists(target_path):
                return jsonify({"error": f"Path '{target_path}' does not exist on disk."}), 400
                
            if os.path.isdir(target_path):
                findings = scan_directory(target_path, scan_git_history=scan_history, config=config)
                gitignore_unignored = audit_gitignore(target_path)
            else:
                findings = scan_file(target_path, config=config)
                
        risk_summary = calculate_security_score(findings)
        return jsonify({
            "findings": findings,
            "risk_summary": risk_summary,
            "gitignore_unignored": gitignore_unignored
        })
    except Exception as e:
        return jsonify({"error": make_error_user_friendly(e)}), 500

@app.route("/api/upload", methods=["POST"])
def upload():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
            
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"error": "No selected file"}), 400
            
        entropy_threshold = float(request.form.get("entropy_threshold", 4.5) or 4.5)
        import json
        disabled_rules_raw = request.form.get("disabled_rules")
        disabled_rules = json.loads(disabled_rules_raw) if disabled_rules_raw else []

        config = {
            "entropy_threshold": entropy_threshold,
            "disabled_rules": disabled_rules
        }

        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, uploaded_file.filename)
        
        uploaded_file.save(temp_path)
        
        findings = []
        if temp_path.lower().endswith(".zip"):
            findings = scan_zip_file(temp_path, config=config)
        else:
            findings = scan_file(temp_path, config=config)
            
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        for f in findings:
            if "::" in f.get("file_path", ""):
                parts = f["file_path"].split("::", 1)
                f["file_path"] = f"{uploaded_file.filename} -> {parts[1]}"
            else:
                f["file_path"] = uploaded_file.filename
            
        risk_summary = calculate_security_score(findings)
        return jsonify({
            "findings": findings,
            "risk_summary": risk_summary,
            "gitignore_unignored": []
        })
    except Exception as e:
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        return jsonify({"error": make_error_user_friendly(e)}), 500

@app.route("/api/explain", methods=["POST"])
def explain_finding():
    data = request.json or {}
    finding = data.get("finding")
    if not finding:
        return jsonify({"error": "Missing finding details"}), 400
        
    explanation = get_ai_explanation(finding)
    return jsonify(explanation)

@app.route("/api/fix/gitignore", methods=["POST"])
def fix_gitignore_route():
    root = "."
    unignored = audit_gitignore(root)
    if not unignored:
        return jsonify({"message": "Clean gitignore audit. No files to ignore."})
        
    success, msg = fix_gitignore(root, unignored)
    if success:
        return jsonify({"message": f"Successfully fixed .gitignore: {msg}"})
    else:
        return jsonify({"error": msg}), 500

@app.route("/api/install-hook", methods=["POST"])
def install_hook_route():
    success, msg = install_pre_commit_hook(".")
    if success:
        return jsonify({"message": f"Git pre-commit hook installed: {msg}"})
    else:
        return jsonify({"error": msg}), 500

def start_web_server(port=5000):
    print(f"🚀 SentinelScan web interface starting on http://127.0.0.1:{port}")
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass
    app.run(host="127.0.0.1", port=port, debug=False)

if __name__ == "__main__":
    start_web_server()
