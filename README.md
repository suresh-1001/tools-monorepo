# Tools – Auto Debug Monorepo

Unified home for my cross‑platform troubleshooting helpers.

- `windows-auto-debug/` – PowerShell toolkit to collect logs, health, and quick fixes.
- `linux-auto-debug/` – Bash toolkit for Ubuntu/AlmaLinux health checks and self‑heal steps.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Repo Type](https://img.shields.io/badge/type-monorepo-blue.svg)](#)

## Quick Start

```bash
# Windows (PowerShell)
cd windows-auto-debug
.\windows-autodebug.ps1 -Verbose

# Linux (bash)
cd linux-auto-debug
chmod +x linux-autodebug.sh
sudo ./linux-autodebug.sh
```

## Repo Layout

```
tools/
├─ windows-auto-debug/   # PowerShell scripts, modules, examples
└─ linux-auto-debug/     # Bash scripts, helpers, examples
```

## Contributing

PRs welcome. Please open issues in **this** repo and tag your platform: `windows` or `linux`.

## Migration Note

This monorepo replaces the individual repositories:
- `windows-auto-debug` → now lives in `/windows-auto-debug`
- `linux-auto-debug` → now lives in `/linux-auto-debug`

The original repos may be archived with a notice that points here.


## Artifacts
- `/docs/` step-by-step with screenshots
- `/scripts/` repeatable automation
- `/dashboards/` sample JSON/PBIX (if relevant)
- `/templates/` redacted policies/SOPs

---
**Contact**  
- Email: **suresh@echand.com**  
- LinkedIn: **linkedin.com/in/sureshchand01**
