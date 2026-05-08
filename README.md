# HOESEC Python Tool for Red Team OPSEC automation - Quick Reference

## Installation

```bash
# Verify Python 3.8+
python3 --version

# Make executable
chmod +x host_opsec_tool.py

# That's it, No external dependencies.
```

## Quick Start

### Interactive Dashboard 
```bash
# Launch interactive dashboard with menu
sudo python3 host_opsec_tool.py
```

Features:
- 🎯 Menu-driven interface
- 📊 Real-time system status display
- 💾 Backup management
- 📜 View logs
- 🧹 Forensic artifact clearing
- ♻️ Full restore functionality

### Command-Line Interface (CLI)
```bash
# Run specific operations from command line
sudo python3 host_opsec_tool.py spoof-all
sudo python3 host_opsec_tool.py status
sudo python3 host_opsec_tool.py restore-all
```

## Basic Commands

### Full Spoofing (CLI)
```bash
sudo python3 host_opsec_tool.py spoof-all
```
Spoofs hostname, MAC addresses, machine IDs, and timezone in one operation.

### Check Current Status (CLI)
```bash
sudo python3 host_opsec_tool.py status
```
Displays current hostname, MACs, machine ID, and timezone.

### Restore Original Values (CLI)
```bash
sudo python3 host_opsec_tool.py restore-all
```
Restores all values from backup. Backup must exist from prior spoof operation.

### Individual Operations (CLI)

```bash
# Hostname only
sudo python3 host_opsec_tool.py spoof-hostname
sudo python3 host_opsec_tool.py restore-hostname

# MAC addresses only
sudo python3 host_opsec_tool.py spoof-mac
sudo python3 host_opsec_tool.py restore-mac

# Machine IDs only
sudo python3 host_opsec_tool.py spoof-machine-id
sudo python3 host_opsec_tool.py restore-machine-id

# Timezone only
sudo python3 host_opsec_tool.py spoof-timezone
sudo python3 host_opsec_tool.py restore-timezone
```

### Clear Forensic Artifacts (CLI)
```bash
sudo python3 host_opsec_tool.py clear-artifacts
```
Clears bash history, system logs, temp files, and cache.

### Custom Backup Location (CLI)
```bash
sudo python3 host_opsec_tool.py spoof-all --backup-dir /tmp/my-backup
```

## Interactive Dashboard Features

The interactive dashboard (`sudo python3 host_opsec_tool.py`) provides:

- **Numbered Menu System:** Easy navigation with numeric selection
- **System Status Display:** View current hostname, MACs, machine ID, and timezone
- **Backup Management:** See backup status and timestamp
- **Log Viewer:** Review operation history with timestamps
- **Forensic Cleaning:** Clear artifacts with confirmation prompt
- **Individual Operations:** Spoof/restore each component separately
- **Vendor MAC Selection:** Choose specific hardware vendors for realistic MAC addresses
- **Color-Coded Feedback:** ✅ Success, ❌ Errors, ⚠️ Warnings

### Vendor MAC Address Selection

When spoofing MAC addresses, you can now:

```bash
# In interactive mode, option [3] for MAC spoofing shows:
Choose spoofing method:
  [1] Random vendor (default)
  [2] Choose specific vendor

# Available vendors include:
  [1] Apple
  [2] Amazon
  [3] Asus
  [4] Broadcom
  [5] Cisco
  [6] Dell
  [7] Google
  [8] HP/Hewlett-Packard
  [9] Intel
  [10] Lenovo
  [11] Microsoft
  [12] Qualcomm
  [13] Ubiquiti
  [14] Arista
```

This ensures your spoofed MAC addresses match real hardware vendors, making fingerprinting detection much harder.

### Example Workflow

```bash
$ sudo python3 host_opsec_tool.py
# → Select [3] for MAC spoofing
# → Select [2] for vendor selection
# → Pick [6] for Dell
# → Tool generates realistic Dell MAC addresses from OUI database
```

## API Integration (Optional)

The tool includes **optional** API integration for real-world vendor lookups without external dependencies. All APIs use built-in `urllib` only.


### Timezone Selection via API

When spoofing timezone (option [5] in interactive menu), the tool now offers:

```
Choose spoofing method:
  [1] Random timezone (default)
  [2] Get timezone suggestions from API ← NEW!
```

Select **[2]** to:
- Fetch timezone list from **restcountries API**
- Display top 15 timezone options with full names
- Select any timezone by number
- Apply selected timezone to system

**Example output:**
```
🌍 Fetching timezone suggestions from API...

Available timezones: 386 total

  [1] Africa/Abidjan
  [2] Africa/Accra
  [3] Africa/Addis_Ababa
  [4] Africa/Algiers
  [5] Africa/Asmara
  ...and 381 more

Select timezone: 245
✓ Using timezone: America/New_York
```



## Backup File Format

JSON-based backup for integrity:

```json
{
  "hostname": "corporate-server-1234",
  "machine_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "timezone": "America/New_York",
  "mac_addresses": {
    "eth0": "00:14:22:ab:cd:ef",
    "eth1": "ec:f4:bb:12:34:56"
  },
  "timestamp": "2026-04-22T15:30:45.123456"
}
```

## Logging

### View Live Log
```bash
tail -f /root/.host-opsec-backups/host-opsec.log
```

### Log Levels
- **DEBUG:** Detailed operation info (file only)
- **INFO:** Important operations (console + file)
- **ERROR:** Failures requiring attention (console + file)

### Example Log Output
```
2026-04-22 15:30:45,123 - __main__ - INFO - ============================================================
2026-04-22 15:30:45,124 - __main__ - INFO - STARTING FULL HOST SPOOFING
2026-04-22 15:30:45,124 - __main__ - INFO - ============================================================
2026-04-22 15:30:45,125 - __main__ - INFO - Backing up hostname configuration
2026-04-22 15:30:45,126 - __main__ - DEBUG - Backed up hostname: original-hostname
2026-04-22 15:30:45,200 - __main__ - INFO - Spoofing hostname
2026-04-22 15:30:45,210 - __main__ - INFO - ✓ Hostname changed to: corporate-server-1234
```

## Troubleshooting

### "Please run as root (use: sudo)"
The tool requires root privileges. Use `sudo`:
```bash
sudo python3 host_opsec_tool.py spoof-all
```

### "No backup available for restoration"
Backup doesn't exist. Run `spoof-all` first to create it:
```bash
sudo python3 host_opsec_tool.py spoof-all
sudo python3 host_opsec_tool.py restore-all
```

### "macchanger not found, installing..."
The tool automatically installs macchanger if needed. Requires `apt-get` access.
If stuck, manually install:
```bash
sudo apt-get update && sudo apt-get install -y macchanger
```

### MAC changes don't persist after reboot
This is normal - depends on network manager configuration. Use systemd service for persistence (future enhancement).

### Need to use custom backup location
```bash
sudo python3 host_opsec_tool.py spoof-all --backup-dir /custom/path
sudo python3 host_opsec_tool.py restore-all --backup-dir /custom/path
```



## Return Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Operation failed |
| 2 | Partial success (some operations failed) |
| 3 | Requires root privileges |

## Advanced: Using in Scripts

```bash
#!/bin/bash
# Spoof host, capture result
if sudo python3 host_opsec_tool.py spoof-all; then
    echo "Spoofing successful"
    # Do something
    sudo python3 host_opsec_tool.py restore-all
else
    echo "Spoofing failed"
    exit 1
fi
```

## Advanced: Reading Logs Programmatically

```python
import json
from pathlib import Path

backup_file = Path('/root/.host-opsec-backups/backup.json')
backup_data = json.loads(backup_file.read_text())

print(f"Spoofed hostname: {backup_data['hostname']}")
print(f"Spoofed MACs: {backup_data['mac_addresses']}")
```

## Standards Met

✅ **Error Handling:** All operations wrapped in try/except  
✅ **Logging:** Comprehensive debug + file logging  
✅ **Type Safety:** Full type hints throughout  
✅ **Atomic Operations:** Backup before spoof; restore on failure  
✅ **Data Validation:** JSON schema validation for backups  
✅ **Documentation:** Inline docstrings for all functions  
✅ **Modularity:** Independent manager classes  
✅ **Testability:** Functions designed for unit testing  

## License

MIT License - See [LICENSE](LICENSE) file for details.
