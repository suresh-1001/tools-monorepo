# windows-auto-debug

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Linux Repo](https://img.shields.io/badge/Linux%20Repo-blue.svg)](https://github.com/suresh-1001/linux-auto-debug)

Windows Auto-Debug + Safe Self-Heal for **Windows Server 2016/2019/2022** and **Windows 10/11**.

- **Read-only by default** → collects system health signals (uptime, CPU/memory hogs, disk usage, services, logs, DNS, time sync, Defender).
- **`-Apply`** → safe self-heal (restart stopped Automatic services, clean temp files, stale Windows Update cache, DISM cleanup, add DNS fallback, resync time).
- **`-Aggressive`** → extends `-Apply` with Microsoft Defender updates + quick scan.
- **Two builds available**:
  - `windows-autodebug.ps1` – ASCII-safe (runs in cmd.exe / legacy PowerShell).
  - `windows-autodebug-plain.ps1` – UTF-8 / emoji (best in Windows Terminal, PowerShell 7+).

---

## 📦 Quick Start

```powershell
# Read-only (ASCII-safe)
powershell -ExecutionPolicy Bypass -File .\windows-autodebug.ps1

# Save a transcript to C:\Temp
powershell -ExecutionPolicy Bypass -File .\windows-autodebug.ps1 -Report "C:\Temp\win-health.txt"

# Apply safe fixes
powershell -ExecutionPolicy Bypass -File .\windows-autodebug.ps1 -Apply

# Apply + Defender quick scan (if available)
powershell -ExecutionPolicy Bypass -File .\windows-autodebug.ps1 -Apply -Aggressive
```

---

## 🔍 What It Checks

- Uptime
- CPU & RAM top offenders
- Total / available memory
- Disk usage by volume
- Network interfaces, routes (top 15), listening ports (top 15)
- Auto-start services that aren’t running
- Recent System & Application **Errors** (last 24h)
- DNS servers per interface
- Windows Time service (w32time) status
- Microsoft Defender status (if installed)
- Biggest files in `C:\Windows\Temp` and user `%TEMP%`

---

## 🛠 Safe Remediations (`-Apply`)

- Restart stopped **Automatic** services
- Clean temp files (>7 days old)
- Clean Windows Update cache (>14 days old)
- Run `DISM /Online /Cleanup-Image /StartComponentCleanup`
- Add DNS fallbacks (`1.1.1.1`, `8.8.8.8`) if no resolvers are set
- Ensure Windows Time (w32time) is running + resync time
- (Optional) Update Defender signatures + run Quick Scan (`-Aggressive`)

---

## 📁 Repo Layout

```
windows-auto-debug/
├─ windows-autodebug.ps1              # ASCII-safe build
├─ windows-autodebug-plain.ps1        # UTF-8 build (emoji)
├─ scripts/
│  ├─ run-readonly.cmd
│  └─ run-apply.cmd
├─ examples/
│  └─ sample-run.txt (add your own transcript here)
├─ CHANGELOG.md
├─ LICENSE
├─ README.md
└─ .gitignore
```

---

## 🚀 Local Git → GitHub Workflow

### On local Git server
```bash
git init --bare /srv/git/windows-auto-debug.git
```

### On your workstation
```bash
git clone user@your-git-server:/srv/git/windows-auto-debug.git
cd windows-auto-debug
# add files, commit, and push
git add .
git commit -m "Initial commit"
git push -u origin main
```

### Push to GitHub
```bash
git remote add github git@github.com:suresh-1001/windows-auto-debug.git
git push -u github main
```

---

## 📌 Notes

- Use `windows-autodebug.ps1` if you see gibberish/emoji issues in cmd.exe.  
- Use `windows-autodebug-plain.ps1` in Windows Terminal / PowerShell 7+ for full Unicode output.  
- Example transcripts are encouraged in `/examples/` so others can preview output.  

---

MIT © 2025 Suresh Chand
