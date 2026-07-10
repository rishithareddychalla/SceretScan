import json
from typing import List, Dict, Any
from sentinel_scan.core.risk_engine import mask_secret

def generate_html_report(
    findings: List[Dict[str, Any]],
    risk_summary: Dict[str, Any],
    gitignore_audit: List[str],
    output_path: str
) -> None:
    """Generates a stunning HTML dashboard report for visual analysis."""
    
    # Prepare findings for JSON embedding (pre-mask the secrets for safety in report)
    safe_findings = []
    for f in findings:
        f_copy = f.copy()
        f_copy["masked_secret"] = mask_secret(f.get("secret", ""))
        f_copy["secret"] = mask_secret(f.get("secret", ""))
        safe_findings.append(f_copy)
        
    score = risk_summary.get("security_score", 100.0)
    grade = risk_summary.get("grade", "A")
    status = risk_summary.get("status", "EXCELLENT")
    counts = risk_summary.get("counts", {})
    
    active_count = len([f for f in findings if not f.get('in_history')])
    history_count = len([f for f in findings if f.get('in_history')])
    total_count = counts.get('TOTAL', 0)
    score_offset = 251.2 - (251.2 * score / 100.0)
    
    # Define HTML Template as standard string (no f-string format errors)
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelScan Security Dashboard</title>
    <!-- Tailwind CSS for layout structure -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js for beautiful charts -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- FontAwesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
                        mono: ['"JetBrains Mono"', 'monospace'],
                    },
                    colors: {
                        dark: {
                            900: '#0B0F19',
                            800: '#111827',
                            700: '#1F2937',
                            600: '#374151',
                        },
                        primary: {
                            500: '#6366F1',
                            600: '#4F46E5',
                            700: '#4338CA',
                        },
                        critical: '#EF4444',
                        high: '#F97316',
                        medium: '#F59E0B',
                        low: '#10B981',
                    }
                }
            }
        }
    </script>
    
    <style>
        body {
            background: linear-gradient(135deg, #0B0F19 0%, #111322 100%);
            color: #E2E8F0;
            min-height: 100vh;
        }
        .glass-panel {
            background: rgba(25, 30, 49, 0.65);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .glass-card-hover:hover {
            transform: translateY(-2px);
            border-color: rgba(99, 102, 241, 0.3);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(99, 102, 241, 0.1);
        }
        .custom-scrollbar::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .glow-critical {
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.15);
        }
        .glow-high {
            box-shadow: 0 0 15px rgba(249, 115, 22, 0.15);
        }
    </style>
</head>
<body class="font-sans antialiased custom-scrollbar">

    <!-- Top Navigation Bar -->
    <header class="sticky top-0 z-50 glass-panel border-b border-white/5 py-4 px-6 md:px-12 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                <i class="fa-solid fa-shield-halved text-white text-xl"></i>
            </div>
            <div>
                <span class="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white via-indigo-200 to-indigo-400 bg-clip-text text-transparent">SentinelScan</span>
                <span class="text-[10px] block text-white/40 font-mono">V1.0.0 • Production Audit</span>
            </div>
        </div>
        
        <div class="flex items-center space-x-4">
            <span class="hidden md:inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-2 animate-pulse"></span>
                Scan Completed
            </span>
            <button onclick="window.print()" class="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm font-medium transition duration-200 flex items-center space-x-2">
                <i class="fa-solid fa-print"></i>
                <span class="hidden sm:inline">Print Report</span>
            </button>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Score Card & Metrics Summary -->
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            
            <!-- Dial gauge / Score card -->
            <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between items-center text-center col-span-1 shadow-xl">
                <h3 class="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-2">Security Score</h3>
                <div class="relative w-40 h-40 flex items-center justify-center">
                    <!-- Progress Ring -->
                    <svg class="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" stroke-width="8" fill="transparent" />
                        <circle id="score-circle" cx="50" cy="50" r="40" stroke="url(#scoreGrad)" stroke-width="8" fill="transparent" 
                                stroke-dasharray="251.2" stroke-dashoffset="__SCORE_OFFSET__" stroke-linecap="round" class="transition-all duration-1000" />
                        <defs>
                            <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stop-color="#4F46E5" />
                                <stop offset="100%" stop-color="#10B981" />
                            </linearGradient>
                        </defs>
                    </svg>
                    <div class="absolute flex flex-col items-center justify-center">
                        <span class="text-4xl font-extrabold text-white tracking-tight">__SCORE__</span>
                        <span class="text-xs text-emerald-400 font-bold uppercase tracking-widest mt-0.5">__STATUS__</span>
                    </div>
                </div>
                <div class="mt-4">
                    <span class="text-xs text-slate-500 block">Security Grade</span>
                    <span class="text-2xl font-black text-white">__GRADE__</span>
                </div>
            </div>
            
            <!-- Severity Metrics -->
            <div class="glass-panel rounded-2xl p-6 col-span-1 lg:col-span-3 flex flex-col justify-between shadow-xl">
                <div>
                    <h3 class="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Severity Breakdown</h3>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        
                        <div class="bg-red-500/5 border border-red-500/10 rounded-xl p-4 flex flex-col items-center justify-center text-center glow-critical">
                            <span class="w-2.5 h-2.5 rounded-full bg-red-500 mb-1"></span>
                            <span class="text-2xl font-extrabold text-white">__CRITICAL_COUNT__</span>
                            <span class="text-xs text-red-400 font-semibold uppercase tracking-wider mt-1">Critical</span>
                        </div>
                        
                        <div class="bg-orange-500/5 border border-orange-500/10 rounded-xl p-4 flex flex-col items-center justify-center text-center glow-high">
                            <span class="w-2.5 h-2.5 rounded-full bg-orange-500 mb-1"></span>
                            <span class="text-2xl font-extrabold text-white">__HIGH_COUNT__</span>
                            <span class="text-xs text-orange-400 font-semibold uppercase tracking-wider mt-1">High</span>
                        </div>
                        
                        <div class="bg-amber-500/5 border border-amber-500/10 rounded-xl p-4 flex flex-col items-center justify-center text-center">
                            <span class="w-2.5 h-2.5 rounded-full bg-amber-500 mb-1"></span>
                            <span class="text-2xl font-extrabold text-white">__MEDIUM_COUNT__</span>
                            <span class="text-xs text-amber-400 font-semibold uppercase tracking-wider mt-1">Medium</span>
                        </div>
                        
                        <div class="bg-emerald-500/5 border border-emerald-500/10 rounded-xl p-4 flex flex-col items-center justify-center text-center">
                            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 mb-1"></span>
                            <span class="text-2xl font-extrabold text-white">__LOW_COUNT__</span>
                            <span class="text-xs text-emerald-400 font-semibold uppercase tracking-wider mt-1">Low</span>
                        </div>
                        
                    </div>
                </div>
                
                <div class="mt-6 flex flex-col sm:flex-row justify-between items-center border-t border-white/5 pt-4 text-xs text-slate-500">
                    <div>
                        <span class="mr-4"><i class="fa-solid fa-folder-open mr-1"></i> Active Files: <strong class="text-white">__ACTIVE_COUNT__</strong></span>
                        <span><i class="fa-solid fa-clock-rotate-left mr-1"></i> Historical Commits: <strong class="text-white">__HISTORY_COUNT__</strong></span>
                    </div>
                    <div class="mt-2 sm:mt-0">
                        <span>Total Findings: <strong class="text-white">__TOTAL_COUNT__</strong></span>
                    </div>
                </div>
            </div>
            
        </div>

        <!-- Tabbed Navigation -->
        <div class="flex border-b border-white/10 mb-8 overflow-x-auto">
            <button onclick="switchTab('tab-dashboard')" id="btn-tab-dashboard" class="px-6 py-3 font-semibold text-sm border-b-2 border-indigo-500 text-white transition-all flex items-center space-x-2">
                <i class="fa-solid fa-chart-pie"></i>
                <span>Analytics</span>
            </button>
            <button onclick="switchTab('tab-findings')" id="btn-tab-findings" class="px-6 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-white transition-all flex items-center space-x-2">
                <i class="fa-solid fa-bug"></i>
                <span>Findings (__TOTAL_COUNT__)</span>
            </button>
            <button onclick="switchTab('tab-timeline')" id="btn-tab-timeline" class="px-6 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-white transition-all flex items-center space-x-2">
                <i class="fa-solid fa-timeline"></i>
                <span>History Timeline</span>
            </button>
            <button onclick="switchTab('tab-audit')" id="btn-tab-audit" class="px-6 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-white transition-all flex items-center space-x-2">
                <i class="fa-solid fa-file-shield"></i>
                <span>.gitignore Audit (__GITIGNORE_AUDIT_COUNT__)</span>
            </button>
        </div>

        <!-- TAB CONTENT: DASHBOARD/ANALYTICS -->
        <div id="tab-dashboard" class="tab-content space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Chart 1: Severity distribution -->
                <div class="glass-panel rounded-2xl p-6 shadow-xl">
                    <h3 class="text-base font-bold text-white mb-4">Findings Severity Weight</h3>
                    <div class="h-64 flex justify-center items-center">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <!-- Chart 2: Category distribution -->
                <div class="glass-panel rounded-2xl p-6 shadow-xl">
                    <h3 class="text-base font-bold text-white mb-4">Findings Category Distribution</h3>
                    <div class="h-64 flex justify-center items-center">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- Quick action cards -->
            <div class="glass-panel rounded-2xl p-6 shadow-xl">
                <h3 class="text-base font-bold text-white mb-4">🔍 Quick Remediation Actions</h3>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div class="bg-indigo-600/10 border border-indigo-500/20 rounded-xl p-4 flex flex-col justify-between">
                        <div>
                            <span class="text-indigo-400 text-xl"><i class="fa-solid fa-code"></i></span>
                            <h4 class="text-sm font-semibold text-white mt-2">Generate .gitignore</h4>
                            <p class="text-xs text-slate-400 mt-1">Audit shows sensitive files. Auto-fix is available to prevent commits.</p>
                        </div>
                        <code class="text-[10px] font-mono bg-black/30 p-2 rounded block mt-4 text-indigo-300">python sentinel.py fix gitignore</code>
                    </div>
                    
                    <div class="bg-indigo-600/10 border border-indigo-500/20 rounded-xl p-4 flex flex-col justify-between">
                        <div>
                            <span class="text-indigo-400 text-xl"><i class="fa-solid fa-anchor"></i></span>
                            <h4 class="text-sm font-semibold text-white mt-2">Install Commit Shield</h4>
                            <p class="text-xs text-slate-400 mt-1">Install a git hook that automatically blocks critical secret commits locally.</p>
                        </div>
                        <code class="text-[10px] font-mono bg-black/30 p-2 rounded block mt-4 text-indigo-300">python sentinel.py install-hook</code>
                    </div>
                    
                    <div class="bg-indigo-600/10 border border-indigo-500/20 rounded-xl p-4 flex flex-col justify-between">
                        <div>
                            <span class="text-indigo-400 text-xl"><i class="fa-solid fa-history"></i></span>
                            <h4 class="text-sm font-semibold text-white mt-2">Compare Scan Snapshots</h4>
                            <p class="text-xs text-slate-400 mt-1">Compare findings with a past snapshot to identify newly introduced secrets.</p>
                        </div>
                        <code class="text-[10px] font-mono bg-black/30 p-2 rounded block mt-4 text-indigo-300">python sentinel.py compare &lt;file&gt;</code>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB CONTENT: FINDINGS -->
        <div id="tab-findings" class="tab-content hidden space-y-4">
            <!-- Search & Filters -->
            <div class="glass-panel rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div class="relative flex-1">
                    <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                        <i class="fa-solid fa-magnifying-glass"></i>
                    </span>
                    <input type="text" id="finding-search" oninput="filterFindings()" placeholder="Search by file path, rule name, or severity..." 
                           class="w-full pl-10 pr-4 py-2 rounded-lg bg-black/20 border border-white/10 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-indigo-500 transition duration-200">
                </div>
                
                <div class="flex items-center space-x-3">
                    <select id="filter-severity" onchange="filterFindings()" 
                            class="bg-dark-700 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                    
                    <select id="filter-source" onchange="filterFindings()" 
                            class="bg-dark-700 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500">
                        <option value="">All Sources</option>
                        <option value="active">Active Files</option>
                        <option value="history">Git History</option>
                    </select>
                </div>
            </div>

            <!-- Findings List container -->
            <div id="findings-list" class="space-y-4">
                <!-- Inserted by JS -->
            </div>
            
            <div id="no-findings" class="hidden text-center py-12 glass-panel rounded-2xl">
                <i class="fa-solid fa-circle-check text-emerald-400 text-5xl mb-4"></i>
                <p class="text-white font-bold text-lg">No secrets match your filter criteria.</p>
                <p class="text-slate-400 text-sm">Try clearing filters or search parameters.</p>
            </div>
        </div>

        <!-- TAB CONTENT: TIMELINE -->
        <div id="tab-timeline" class="tab-content hidden space-y-6">
            <div class="glass-panel rounded-2xl p-6 shadow-xl">
                <h3 class="text-base font-bold text-white mb-6">⏳ Secret Leak Timeline (Git History)</h3>
                
                <div class="relative border-l border-white/10 pl-6 ml-4 space-y-8" id="timeline-container">
                    <!-- Inserted by JS -->
                </div>
                
                <div id="empty-history" class="hidden text-center py-8">
                    <i class="fa-solid fa-code-commit text-slate-500 text-4xl mb-3"></i>
                    <p class="text-slate-400">No secret leaks detected in Git commit history.</p>
                </div>
            </div>
        </div>

        <!-- TAB CONTENT: .GITIGNORE AUDIT -->
        <div id="tab-audit" class="tab-content hidden space-y-6">
            <div class="glass-panel rounded-2xl p-6 shadow-xl">
                <h3 class="text-base font-bold text-white mb-4">🛡️ .gitignore Audit Status</h3>
                
                <div id="audit-results-container">
                    <!-- Inserted by JS -->
                </div>
            </div>
        </div>

    </main>

    <footer class="text-center py-8 border-t border-white/5 text-xs text-slate-500 mt-12">
        <p>SentinelScan Security Platform • Built by Pair Programming Assistant</p>
    </footer>

    <!-- Inject data safely as JSON -->
    <script>
        const findingsData = __SAFE_FINDINGS_JSON__;
        const gitignoreAuditData = __GITIGNORE_AUDIT_JSON__;
        const scoreVal = __SCORE_VAL__;
    </script>
    
    <!-- Render logic -->
    <script>
        // Tab switching
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.getElementById(tabId).classList.remove('hidden');
            
            // Update active states
            const tabs = ['tab-dashboard', 'tab-findings', 'tab-timeline', 'tab-audit'];
            tabs.forEach(t => {
                const btn = document.getElementById('btn-' + t);
                if (t === tabId) {
                    btn.classList.add('border-indigo-500', 'text-white');
                    btn.classList.remove('border-transparent', 'text-slate-400');
                } else {
                    btn.classList.remove('border-indigo-500', 'text-white');
                    btn.classList.add('border-transparent', 'text-slate-400');
                }
            });
        }
        
        // Severity color mapping
        function getSeverityBadge(severity) {
            const sev = severity.toUpperCase();
            if (sev === 'CRITICAL') return '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">CRITICAL</span>';
            if (sev === 'HIGH') return '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-orange-500/10 text-orange-400 border border-orange-500/20">HIGH</span>';
            if (sev === 'MEDIUM') return '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-emerald-500/20">MEDIUM</span>';
            return '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">LOW</span>';
        }
        
        function renderFindingsList(list) {
            const container = document.getElementById('findings-list');
            if (list.length === 0) {
                container.innerHTML = '';
                document.getElementById('no-findings').classList.remove('hidden');
                return;
            }
            document.getElementById('no-findings').classList.add('hidden');
            
            container.innerHTML = list.map((f, index) => {
                const type = f.in_history ? 
                    `<span class="text-xs bg-slate-500/10 border border-slate-500/20 text-slate-400 px-2 py-0.5 rounded flex items-center space-x-1"><i class="fa-solid fa-clock-rotate-left"></i> <span>Git History</span></span>` : 
                    `<span class="text-xs bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded flex items-center space-x-1"><i class="fa-solid fa-file-code"></i> <span>Active File</span></span>`;
                
                const codeLine = f.line_content ? 
                    `<div class="bg-black/30 p-3 rounded-lg border border-white/5 font-mono text-xs overflow-x-auto text-slate-300 mt-3 select-all">
                        <code>${escapeHtml(f.line_content)}</code>
                     </div>` : '';
                     
                const detailsId = `details-${index}`;
                
                return `
                <div class="glass-panel rounded-xl p-5 transition duration-200 hover:border-white/10">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="flex items-center space-x-3 flex-wrap gap-y-2">
                            <span class="font-bold text-white text-sm sm:text-base">${escapeHtml(f.rule_name)}</span>
                            ${getSeverityBadge(f.severity)}
                            ${type}
                        </div>
                        <span class="text-xs font-mono text-slate-500">${escapeHtml(f.category || 'Secret')}</span>
                    </div>
                    
                    <div class="mt-2 text-sm text-slate-300 flex items-center space-x-2">
                        <i class="fa-regular fa-folder text-slate-500"></i>
                        <span class="font-mono text-xs select-all text-slate-400">${escapeHtml(f.file_path)}</span>
                        ${f.line_number ? `<span class="text-slate-500 font-mono text-xs">L${f.line_number}:${f.start_column}</span>` : ''}
                    </div>
                    
                    ${codeLine}
                    
                    <div class="mt-4 flex justify-between items-center border-t border-white/5 pt-3">
                        <button onclick="toggleDetails('${detailsId}')" class="text-xs font-medium text-indigo-400 hover:text-indigo-300 transition duration-150 flex items-center space-x-1">
                            <span id="btn-text-${detailsId}">Show Risk Details & Remediation</span>
                            <i id="btn-icon-${detailsId}" class="fa-solid fa-chevron-down"></i>
                        </button>
                        <span class="text-[10px] font-mono text-slate-600">ID: ${escapeHtml(f.rule_id)}</span>
                    </div>
                    
                    <!-- Expandable info -->
                    <div id="${detailsId}" class="hidden mt-4 border-t border-white/5 pt-4 space-y-4 text-xs sm:text-sm text-slate-300 transition-all duration-300">
                        <div class="bg-indigo-950/10 border border-indigo-500/10 p-4 rounded-xl">
                            <span class="font-bold text-indigo-300 block mb-1">🛡️ Risk Description</span>
                            <p class="text-slate-400">${escapeHtml(f.description || 'No description provided.')}</p>
                        </div>
                        <div class="bg-emerald-950/10 border border-emerald-500/10 p-4 rounded-xl">
                            <span class="font-bold text-emerald-300 block mb-1">💡 Auto-Fix & Remediation</span>
                            <p class="text-slate-400">${escapeHtml(f.remediation || 'No remediation provided.')}</p>
                        </div>
                        ${f.commit_hash ? `
                        <div class="bg-slate-900/40 border border-white/5 p-4 rounded-xl font-mono text-xs space-y-1">
                            <span class="font-bold text-slate-300 block mb-1"><i class="fa-solid fa-code-commit mr-1"></i> Commit Metadata</span>
                            <div>Hash: <span class="text-indigo-400 font-semibold select-all">${f.commit_hash}</span></div>
                            <div>Author: <span class="text-slate-400">${escapeHtml(f.commit_author)}</span></div>
                            <div>Date: <span class="text-slate-400">${f.commit_date}</span></div>
                            <div>Message: <span class="text-slate-400">"${escapeHtml(f.commit_message)}"</span></div>
                        </div>
                        ` : ''}
                    </div>
                </div>
                `;
            }).join('');
        }
        
        function toggleDetails(id) {
            const el = document.getElementById(id);
            const btnText = document.getElementById('btn-text-' + id);
            const btnIcon = document.getElementById('btn-icon-' + id);
            if (el.classList.contains('hidden')) {
                el.classList.remove('hidden');
                btnText.innerText = 'Hide Details';
                btnIcon.classList.replace('fa-chevron-down', 'fa-chevron-up');
            } else {
                el.classList.add('hidden');
                btnText.innerText = 'Show Risk Details & Remediation';
                btnIcon.classList.replace('fa-chevron-up', 'fa-chevron-down');
            }
        }
        
        function filterFindings() {
            const query = document.getElementById('finding-search').value.toLowerCase();
            const severity = document.getElementById('filter-severity').value;
            const source = document.getElementById('filter-source').value;
            
            const filtered = findingsData.filter(f => {
                const matchesQuery = 
                    f.file_path.toLowerCase().includes(query) ||
                    f.rule_name.toLowerCase().includes(query) ||
                    (f.line_content && f.line_content.toLowerCase().includes(query));
                    
                const matchesSeverity = severity === "" || f.severity.toUpperCase() === severity.toUpperCase();
                
                const matchesSource = 
                    source === "" ||
                    (source === "active" && !f.in_history) ||
                    (source === "history" && f.in_history);
                    
                return matchesQuery && matchesSeverity && matchesSource;
            });
            
            renderFindingsList(filtered);
        }
        
        // Render Timeline
        function renderTimeline() {
            const history = findingsData.filter(f => f.in_history);
            const container = document.getElementById('timeline-container');
            const emptyEl = document.getElementById('empty-history');
            
            if (history.length === 0) {
                emptyEl.classList.remove('hidden');
                container.innerHTML = '';
                return;
            }
            emptyEl.classList.add('hidden');
            
            // Sort history by date descending
            history.sort((a,b) => new Date(b.commit_date) - new Date(a.commit_date));
            
            container.innerHTML = history.map(h => `
                <div class="relative pl-2">
                    <span class="absolute -left-[31px] top-1.5 w-4 h-4 rounded-full bg-indigo-500 border border-[#0B0F19] ring-4 ring-indigo-500/10 flex items-center justify-center"></span>
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-500 mb-1">
                        <div class="flex items-center space-x-2">
                            <span class="font-bold text-indigo-400 font-mono select-all">${h.commit_hash.substring(0, 8)}</span>
                            <span>•</span>
                            <span class="font-medium text-slate-400">${escapeHtml(h.commit_author)}</span>
                        </div>
                        <span>${new Date(h.commit_date).toLocaleString()}</span>
                    </div>
                    <div class="glass-panel border-white/5 rounded-xl p-4">
                        <span class="text-xs uppercase font-mono tracking-wider font-bold block mb-1 text-slate-500">${h.category}</span>
                        <div class="flex items-center space-x-2 mb-2">
                            <span class="font-bold text-white text-sm">${escapeHtml(h.rule_name)}</span>
                            ${getSeverityBadge(h.severity)}
                        </div>
                        <div class="text-xs text-slate-400 font-mono truncate mb-2">File: ${escapeHtml(h.file_path)}</div>
                        <div class="text-xs italic text-slate-500">" ${escapeHtml(h.commit_message)} "</div>
                    </div>
                </div>
            `).join('');
        }
        
        // Render gitignore audit
        function renderGitignoreAudit() {
            const container = document.getElementById('audit-results-container');
            if (gitignoreAuditData.length === 0) {
                container.innerHTML = `
                <div class="text-center py-8">
                    <i class="fa-solid fa-shield text-emerald-400 text-5xl mb-4"></i>
                    <p class="text-white font-bold text-lg">Your Workspace is Clean</p>
                    <p class="text-slate-400 text-sm mt-1">All sensitive file types (such as .env, private keys) are properly listed in your .gitignore file.</p>
                </div>`;
                return;
            }
            
            container.innerHTML = `
            <div class="bg-red-500/5 border border-red-500/10 rounded-xl p-5 mb-6">
                <h4 class="font-bold text-red-400 flex items-center space-x-2 text-sm sm:text-base mb-2">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <span>Unignored Sensitive Files Found!</span>
                </h4>
                <p class="text-slate-400 text-xs sm:text-sm">The following files contain config/secrets and are present in your workspace, but they are NOT ignored in your .gitignore file. They are vulnerable to being checked into git repository history.</p>
            </div>
            
            <div class="space-y-2 mb-6">
                ${gitignoreAuditData.map(file => `
                    <div class="bg-black/20 border border-white/5 rounded-lg px-4 py-3 flex justify-between items-center font-mono text-xs sm:text-sm">
                        <span class="text-red-400"><i class="fa-solid fa-file-excel mr-2"></i>${escapeHtml(file)}</span>
                        <span class="text-slate-500 select-all">Add to .gitignore</span>
                    </div>
                `).join('')}
            </div>
            
            <div class="bg-indigo-600/5 border border-indigo-500/10 p-5 rounded-xl text-xs sm:text-sm">
                <span class="font-bold text-white block mb-1">💡 Auto-Fix Recommendation</span>
                <p class="text-slate-400">Run the SentinelScan autofix tool in your workspace directory to immediately append these paths to your \`.gitignore\` configuration:</p>
                <code class="block font-mono bg-black/40 p-3 rounded-lg border border-white/5 text-indigo-300 mt-3 select-all">python sentinel.py fix gitignore</code>
            </div>`;
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, function(m) { return map[m]; });
        }
        
        // Initialize charts
        document.addEventListener("DOMContentLoaded", () => {
            renderFindingsList(findingsData);
            renderTimeline();
            renderGitignoreAudit();
            
            // Build analytics charts
            const severityCounts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0};
            const categoryCounts = {};
            
            findingsData.forEach(f => {
                const sev = f.severity.toUpperCase();
                if (severityCounts[sev] !== undefined) severityCounts[sev]++;
                
                const cat = f.category || "Other";
                categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
            });
            
            // Severity Chart
            new Chart(document.getElementById('severityChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [severityCounts.CRITICAL, severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW],
                        backgroundColor: ['#EF4444', '#F97316', '#F59E0B', '#10B981'],
                        borderColor: '#111827',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#94A3B8', font: { family: 'Plus Jakarta Sans' } }
                        }
                    }
                }
            });
            
            // Category Chart
            const catLabels = Object.keys(categoryCounts);
            const catData = Object.values(categoryCounts);
            
            new Chart(document.getElementById('categoryChart'), {
                type: 'bar',
                data: {
                    labels: catLabels,
                    datasets: [{
                        label: 'Leaks Count',
                        data: catData,
                        backgroundColor: '#6366F1',
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            ticks: { color: '#94A3B8', font: { family: 'Plus Jakarta Sans' } },
                            grid: { color: 'rgba(255,255,255,0.05)' }
                        },
                        x: {
                            ticks: { color: '#94A3B8', font: { family: 'Plus Jakarta Sans' } },
                            grid: { display: false }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        });
    </script>
</body>
</html>
"""
    
    # Safely substitute placeholders
    html_content = html_template
    html_content = html_content.replace("__SCORE_OFFSET__", str(score_offset))
    html_content = html_content.replace("__SCORE__", str(int(score) if score.is_integer() else score))
    html_content = html_content.replace("__STATUS__", status)
    html_content = html_content.replace("__GRADE__", grade)
    html_content = html_content.replace("__CRITICAL_COUNT__", str(counts.get('CRITICAL', 0)))
    html_content = html_content.replace("__HIGH_COUNT__", str(counts.get('HIGH', 0)))
    html_content = html_content.replace("__MEDIUM_COUNT__", str(counts.get('MEDIUM', 0)))
    html_content = html_content.replace("__LOW_COUNT__", str(counts.get('LOW', 0)))
    html_content = html_content.replace("__ACTIVE_COUNT__", str(active_count))
    html_content = html_content.replace("__HISTORY_COUNT__", str(history_count))
    html_content = html_content.replace("__TOTAL_COUNT__", str(total_count))
    html_content = html_content.replace("__GITIGNORE_AUDIT_COUNT__", str(len(gitignore_audit)))
    html_content = html_content.replace("__SAFE_FINDINGS_JSON__", json.dumps(safe_findings))
    html_content = html_content.replace("__GITIGNORE_AUDIT_JSON__", json.dumps(gitignore_audit))
    html_content = html_content.replace("__SCORE_VAL__", str(score))
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
