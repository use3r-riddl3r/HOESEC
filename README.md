# HOESEC Python Tool for Red Team OPSEC automation 

A small tool/script i use for convenience, just to be lazy and not run 5/6 diffrent individual commands :))


## Installation

```bash
# Verify Python 3.8+
python3 --version

# Make executable
chmod +x host_opsec_tool.py

## Quick Start

### Interactive Dashboard 
```bash
# Launch interactive dashboard with menu
sudo python3 host_opsec_tool.py
```

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


The interactive dashboard (`sudo python3 host_opsec_tool.py`) provides:


### Vendor MAC Address Selection

When spoofing MAC addresses; gives choices

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

ensuring your spoofed MAC addresses match real hardware vendors, making fingerprinting detection much harder.



## API Integration 

I included **optional** API integration for real world vendor lookups without external dependencies. All APIs use built-in `urllib` only.


### Timezone Selection via API

When spoofing timezone , the tool now offers:

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



##  Using in Scripts

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

``

## Build Notes:

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
