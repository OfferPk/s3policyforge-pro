/\* S3PolicyForge Pro \- Cloud Security Dark Theme \*/

:root {  
  \--bg-primary: \#070a14;  
  \--bg-secondary: \#0c1122;  
  \--bg-card: \#0e152a;  
  \--bg-card-hover: \#131c38;  
  \--border-color: \#1a2544;  
  \--border-accent: \#2a3a68;  
  \--text-main: \#f8fafc;  
  \--text-muted: \#94a3b8;  
  \--text-sub: \#64748b;  
  \--accent-cyan: \#06b6d4;  
  \--accent-blue: \#3b82f6;  
  \--accent-green: \#10b981;  
  \--accent-amber: \#f59e0b;  
  \--accent-red: \#ef4444;  
  \--accent-purple: \#8b5cf6;  
  \--font-sans: \-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;  
  \--font-mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace;  
}

\* {  
  box-sizing: border-box;  
  margin: 0;  
  padding: 0;  
}

body {  
  background-color: var(--bg-primary);  
  color: var(--text-main);  
  font-family: var(--font-sans);  
  line-height: 1.5;  
  padding: 24px;  
  \-webkit-font-smoothing: antialiased;  
}

.app-container {  
  max-width: 1400px;  
  margin: 0 auto;  
}

/\* Header \*/  
header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  padding: 18px 24px;  
  background: var(--bg-card);  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  margin-bottom: 24px;  
}

.logo-area {  
  display: flex;  
  align-items: center;  
  gap: 14px;  
}

.logo-badge {  
  background: linear-gradient(135deg, \#f59e0b, \#ef4444);  
  color: \#fff;  
  font-weight: 800;  
  font-size: 14px;  
  padding: 8px 12px;  
  border-radius: 8px;  
  letter-spacing: 0.5px;  
}

h1 {  
  font-size: 20px;  
  font-weight: 700;  
  letter-spacing: \-0.5px;  
  display: flex;  
  align-items: center;  
  gap: 10px;  
}

.version-pill {  
  font-size: 11px;  
  background: rgba(6, 182, 212, 0.15);  
  color: var(--accent-cyan);  
  border: 1px solid rgba(6, 182, 212, 0.4);  
  padding: 2px 8px;  
  border-radius: 12px;  
  font-weight: 600;  
}

.header-badges {  
  display: flex;  
  gap: 10px;  
}

.badge {  
  font-size: 11px;  
  font-weight: 600;  
  padding: 5px 12px;  
  border-radius: 20px;  
  text-transform: uppercase;  
  letter-spacing: 0.5px;  
}

.badge-cyan {  
  background: rgba(6, 182, 212, 0.12);  
  color: var(--accent-cyan);  
  border: 1px solid rgba(6, 182, 212, 0.35);  
}

.badge-green {  
  background: rgba(16, 185, 129, 0.12);  
  color: var(--accent-green);  
  border: 1px solid rgba(16, 185, 129, 0.35);  
}

/\* Presets Bar \*/  
.presets-bar {  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
  background: var(--bg-secondary);  
  border: 1px solid var(--border-color);  
  border-radius: 10px;  
  padding: 14px 20px;  
  margin-bottom: 24px;  
  flex-wrap: wrap;  
  gap: 14px;  
}

.preset-selector-group {  
  display: flex;  
  align-items: center;  
  gap: 12px;  
}

.preset-selector-group label {  
  font-size: 13px;  
  font-weight: 600;  
  color: var(--text-muted);  
}

select, input, textarea {  
  background: \#080c1a;  
  border: 1px solid var(--border-accent);  
  color: var(--text-main);  
  padding: 8px 12px;  
  border-radius: 6px;  
  font-size: 13px;  
  font-family: inherit;  
  outline: none;  
  transition: border-color 0.2s;  
}

select:focus, input:focus, textarea:focus {  
  border-color: var(--accent-cyan);  
}

.btn {  
  background: var(--bg-card);  
  border: 1px solid var(--border-accent);  
  color: var(--text-main);  
  padding: 8px 16px;  
  border-radius: 6px;  
  font-size: 13px;  
  font-weight: 600;  
  cursor: pointer;  
  display: inline-flex;  
  align-items: center;  
  gap: 6px;  
  transition: all 0.2s ease;  
}

.btn:hover {  
  background: var(--bg-card-hover);  
  border-color: var(--accent-cyan);  
  color: \#fff;  
}

.btn-primary {  
  background: linear-gradient(135deg, \#0891b2, \#2563eb);  
  border: none;  
  color: \#fff;  
}

.btn-primary:hover {  
  background: linear-gradient(135deg, \#06b6d4, \#3b82f6);  
}

/\* Grid Layout \*/  
.main-grid {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 24px;  
  margin-bottom: 24px;  
}

@media (max-width: 1080px) {  
  .main-grid {  
    grid-template-columns: 1fr;  
  }  
}

.card {  
  background: var(--bg-card);  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  padding: 20px;  
}

.card-header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  margin-bottom: 18px;  
  padding-bottom: 12px;  
  border-bottom: 1px solid var(--border-color);  
}

.card-title {  
  font-size: 15px;  
  font-weight: 700;  
  display: flex;  
  align-items: center;  
  gap: 8px;  
}

/\* Forms & Rows \*/  
.form-row {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 14px;  
  margin-bottom: 14px;  
}

.form-group {  
  display: flex;  
  flex-direction: column;  
  gap: 6px;  
}

.form-group label {  
  font-size: 12px;  
  color: var(--text-muted);  
  font-weight: 600;  
}

/\* Quick Toggle Grid \*/  
.toggle-grid {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 12px;  
  margin-top: 14px;  
  margin-bottom: 16px;  
}

.toggle-card {  
  background: \#080c1a;  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 12px;  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
}

.toggle-label {  
  font-size: 12px;  
  font-weight: 600;  
  color: var(--text-main);  
}

.toggle-desc {  
  font-size: 10px;  
  color: var(--text-muted);  
}

/\* Scorecard \*/  
.score-banner {  
  display: flex;  
  align-items: center;  
  gap: 20px;  
  background: \#080c1a;  
  border: 1px solid var(--border-color);  
  border-radius: 10px;  
  padding: 16px;  
  margin-bottom: 18px;  
}

.score-circle {  
  width: 70px;  
  height: 70px;  
  border-radius: 50%;  
  display: flex;  
  flex-direction: column;  
  justify-content: center;  
  align-items: center;  
  border: 3px solid var(--accent-green);  
  background: rgba(16, 185, 129, 0.1);  
  flex-shrink: 0;  
}

.score-num {  
  font-size: 20px;  
  font-weight: 800;  
  font-family: var(--font-mono);  
  line-height: 1;  
}

.score-label {  
  font-size: 9px;  
  text-transform: uppercase;  
  font-weight: 700;  
  color: var(--text-muted);  
}

.score-summary h3 {  
  font-size: 16px;  
  font-weight: 700;  
  margin-bottom: 4px;  
}

.score-summary p {  
  font-size: 12px;  
  color: var(--text-muted);  
}

.checklist {  
  display: flex;  
  flex-direction: column;  
  gap: 10px;  
}

.check-item {  
  display: flex;  
  align-items: flex-start;  
  gap: 12px;  
  background: \#080c1a;  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 10px 14px;  
}

.check-icon {  
  font-size: 14px;  
  margin-top: 2px;  
}

.check-content {  
  flex: 1;  
}

.check-title-row {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  margin-bottom: 2px;  
}

.check-title {  
  font-size: 12px;  
  font-weight: 600;  
  color: var(--text-main);  
}

.check-pts {  
  font-size: 11px;  
  font-family: var(--font-mono);  
  font-weight: 700;  
}

.check-pts.pass { color: var(--accent-green); }  
.check-pts.warn { color: var(--accent-amber); }  
.check-pts.fail { color: var(--accent-red); }

.check-desc {  
  font-size: 11px;  
  color: var(--text-muted);  
}

/\* Synthesizer Tabs \*/  
.tabs-bar {  
  display: flex;  
  gap: 8px;  
  border-bottom: 1px solid var(--border-color);  
  padding-bottom: 12px;  
  margin-bottom: 14px;  
  overflow-x: auto;  
}

.tab-btn {  
  background: transparent;  
  border: 1px solid transparent;  
  color: var(--text-muted);  
  font-size: 12px;  
  font-weight: 600;  
  padding: 6px 14px;  
  border-radius: 6px;  
  cursor: pointer;  
  transition: all 0.2s;  
  white-space: nowrap;  
}

.tab-btn:hover {  
  color: var(--text-main);  
  background: rgba(255, 255, 255, 0.04);  
}

.tab-btn.active {  
  background: rgba(6, 182, 212, 0.12);  
  color: var(--accent-cyan);  
  border-color: rgba(6, 182, 212, 0.35);  
}

.code-output {  
  background: \#030611;  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 14px;  
  font-family: var(--font-mono);  
  font-size: 12px;  
  color: \#38bdf8;  
  white-space: pre-wrap;  
  word-break: break-all;  
  height: 280px;  
  overflow-y: auto;  
  line-height: 1.6;  
}

.copy-row {  
  display: flex;  
  justify-content: flex-end;  
  margin-top: 10px;  
}  
