package main

const authbrokerCSP = "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'none'; img-src 'self'; manifest-src 'none'; object-src 'none'; script-src 'self'; style-src 'self'"

const authbrokerCSS = `
:root {
  color-scheme: dark;
  --page: #0b1220;
  --panel: #131c2c;
  --panel-soft: #1a2333;
  --text: #e6ebf2;
  --muted: #94a3b8;
  --line: #243042;
  --line-strong: #334155;
  --brand: #14b8a6;
  --brand-strong: #0d9488;
  --accent: #60a5fa;
  --danger: #f87171;
  --shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background:
    linear-gradient(180deg, rgba(20, 184, 166, 0.10), rgba(96, 165, 250, 0.05) 38%, transparent 72%),
    var(--page);
  color: var(--text);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.5;
}

a {
  color: var(--accent);
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

code,
textarea {
  font-family: var(--mono);
}

.shell {
  width: min(1120px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 48px;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 22px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  border-radius: 8px;
  background: var(--brand);
  color: #ffffff;
  font-weight: 800;
}

.brand-title {
  margin: 0;
  font-size: 22px;
  line-height: 1.15;
}

.brand-subtitle,
.muted {
  color: var(--muted);
}

.brand-subtitle {
  margin-top: 3px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 0 12px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--panel);
  color: var(--muted);
  font-weight: 650;
}

.layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 18px;
  align-items: start;
}

.panel,
.token-row,
.login-panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: var(--shadow);
}

.panel {
  padding: 22px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  gap: 14px;
  align-items: start;
  margin-bottom: 18px;
}

.panel-title {
  margin: 0;
  font-size: 18px;
}

.section-kicker {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 750;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.token-list {
  display: grid;
  gap: 12px;
}

.token-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  padding: 16px;
  box-shadow: none;
}

.token-name {
  margin: 0 0 8px;
  font-size: 16px;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 14px;
}

.meta-label {
  display: block;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
}

.meta-value {
  display: block;
  overflow-wrap: anywhere;
}

.side-stack {
  display: grid;
  gap: 14px;
}

.identity-block {
  display: grid;
  gap: 8px;
}

.identity-line {
  margin: 0;
}

.issued-token {
  margin-top: 18px;
  border-top: 1px solid var(--line);
  padding-top: 18px;
}

.token-output {
  display: block;
  width: 100%;
  min-height: 160px;
  resize: vertical;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: 12px;
  background: #0f172a;
  color: #dbeafe;
  font-size: 12px;
  line-height: 1.45;
}

.actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-top: 14px;
}

.button,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 0 14px;
  border: 1px solid transparent;
  border-radius: 8px;
  background: var(--brand);
  color: #ffffff;
  font: inherit;
  font-weight: 750;
  cursor: pointer;
}

.button:hover,
button:hover {
  background: var(--brand-strong);
  text-decoration: none;
}

.button.secondary,
button.secondary {
  border-color: var(--line-strong);
  background: var(--panel-soft);
  color: var(--text);
}

.button.secondary:hover,
button.secondary:hover {
  background: var(--panel);
}

button.danger {
  background: var(--danger);
}

.copy-status {
  color: var(--muted);
  font-size: 13px;
  font-weight: 650;
}

.empty-state,
.login-panel {
  max-width: 480px;
  margin: 0 auto;
  padding: 28px;
}

.empty-state {
  text-align: center;
}

.empty-state h2,
.login-panel h1 {
  margin: 0 0 8px;
  font-size: 24px;
}

.form-grid {
  display: grid;
  gap: 16px;
}

.field {
  display: grid;
  gap: 7px;
}

.field span {
  font-weight: 700;
}

.field input {
  width: 100%;
  min-height: 42px;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: 0 12px;
  color: var(--text);
  font: inherit;
  background: var(--panel-soft);
}

.field input::placeholder {
  color: var(--muted);
}

.field input:focus,
.token-output:focus {
  outline: 3px solid rgba(96, 165, 250, 0.35);
  border-color: var(--accent);
}

.logout-panel {
  max-width: 560px;
  margin: 40px auto 0;
}

.logout-actions {
  margin-top: 18px;
}

@media (max-width: 800px) {
  .shell {
    width: min(100% - 20px, 1120px);
    padding-top: 18px;
  }

  .topbar,
  .panel-header,
  .token-row {
    align-items: stretch;
    flex-direction: column;
  }

  .layout,
  .meta-grid,
  .token-row {
    grid-template-columns: 1fr;
  }

  .status-pill {
    width: fit-content;
  }
}
`

const authbrokerJS = `
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy-target]");
  if (!button) {
    return;
  }
  var target = document.getElementById(button.getAttribute("data-copy-target"));
  if (!target || !navigator.clipboard) {
    return;
  }
  navigator.clipboard.writeText(target.value).then(function () {
    var status = document.querySelector("[data-copy-status]");
    if (status) {
      status.textContent = "Copied";
      window.setTimeout(function () {
        status.textContent = "";
      }, 1800);
    }
  });
});
`
