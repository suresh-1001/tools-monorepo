# Linux Secure Check & Hardening

Automated script for Ubuntu and AlmaLinux that performs:
- Security audit
- SSH hardening (disable root login & password auth)
- Firewall configuration (UFW/Firewalld)
- Password policies
- Rootkit & malware scans
- Log cleanup & rotation
- Auditd setup  
- **Rollback option** to restore previous settings

## Usage
```bash
sudo bash linux-secure-check.sh --harden --allow "80,443"
sudo bash linux-secure-check.sh --check
sudo bash linux-secure-check.sh --rollback
