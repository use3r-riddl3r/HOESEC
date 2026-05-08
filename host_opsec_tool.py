#!/usr/bin/env python3
"""
HOESEC Red Team Host-Level OPSEC Automation

A tool for spoofing and managing host identifiers
including hostname, MAC addresses, machine IDs, and timezone.

Features:
    - Atomic operations with automatic rollback on failure
    - Comprehensive backup/restore functionality
    - Forensic artifact clearing
    - Persistent configuration across reboots
    - Detailed logging and validation
"""

import os
import sys
import json
import random
import shutil
import logging
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from enum import Enum
from urllib import request
from urllib.error import URLError, HTTPError


class OperationStatus(Enum):
    """Status codes for operations."""
    SUCCESS = 0
    FAILURE = 1
    PARTIAL = 2
    REQUIRES_ROOT = 3


class APIHelper:
    """Helper for optional API calls (MAC vendor, timezone)."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.timeout = 5

    def fetch_mac_vendor(self, mac_address: str) -> Optional[str]:
        """Fetch vendor name from macaddress.io API."""
        try:
            url = f"https://api.macaddress.io/v1?output=json&search={mac_address}"
            req = request.Request(url)
            req.add_header('User-Agent', 'HOST-OPSEC/1.0')

            with request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read())
                vendor = data.get('vendorDetails', {}).get('companyName')
                return vendor

        except (URLError, HTTPError, json.JSONDecodeError, KeyError) as e:
            self.logger.debug("MAC vendor lookup failed: %s", e)
            return None

    def fetch_timezone_from_ip(self, ip: str = None) -> Optional[str]:
        """Fetch timezone from IP location (uses public IP if none provided)."""
        try:
            if not ip:
                # Get public IP first
                ipify_url = "https://api.ipify.org?format=json"
                with request.urlopen(ipify_url, timeout=self.timeout) as response:
                    ip_data = json.loads(response.read())
                    ip = ip_data.get('ip')

            if not ip:
                return None

            url = f"https://ipapi.co/{ip}/json/"
            req = request.Request(url)
            req.add_header('User-Agent', 'HOST-OPSEC/1.0')

            with request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read())
                timezone = data.get('timezone')
                country = data.get('country_name')

                if timezone:
                    self.logger.debug("Timezone from IP: %s (%s)", timezone, country)
                    return timezone

        except (URLError, HTTPError, json.JSONDecodeError, KeyError) as e:
            self.logger.debug("Timezone lookup failed: %s", e)
            return None

    def fetch_macs_by_vendor(self, vendor: str) -> Optional[List[str]]:
        """Fetch multiple MACs for a specific vendor from API."""
        try:
            # Try to fetch OUI data from API
            # Using macaddress.io or similar OUI lookup
            url = f"https://api.macaddress.io/v1?output=json&search={vendor}"
            req = request.Request(url)
            req.add_header('User-Agent', 'HOST-OPSEC/1.0')

            with request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read())
                # If successful, vendor exists and has MACs
                vendor_name = data.get('vendorDetails', {}).get('companyName')
                if vendor_name:
                    self.logger.debug("Found vendor in API: %s", vendor_name)
                    return [vendor_name]  # Return found vendor

            return None

        except (URLError, HTTPError, json.JSONDecodeError, KeyError) as e:
            self.logger.debug("Vendor MAC lookup failed: %s", e)
            return None

    def lookup_timezones_by_country(self, country_hint: str = None) -> Optional[List[str]]:
        """Get list of timezones (from API or hardcoded fallback)."""
        try:
            # Try to get from API first
            url = "https://restcountries.com/v3.1/all"
            req = request.Request(url)
            req.add_header('User-Agent', 'HOST-OPSEC/1.0')

            with request.urlopen(req, timeout=self.timeout) as response:
                countries = json.loads(response.read())
                all_timezones = set()

                for country in countries:
                    if country_hint and country_hint.lower() not in str(country).lower():
                        continue
                    timezones = country.get('timezones', [])
                    all_timezones.update(timezones)

                return sorted(list(all_timezones))

        except (URLError, HTTPError, json.JSONDecodeError) as e:
            self.logger.debug("Timezone list lookup failed: %s", e)
            return None


@dataclass
class BackupData:
    """Container for backed up system configuration."""
    hostname: Optional[str] = None
    hostname_file: Optional[str] = None
    hosts_file: Optional[str] = None
    machine_id: Optional[str] = None
    dbus_machine_id: Optional[str] = None
    timezone: Optional[str] = None
    mac_addresses: Dict[str, str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.mac_addresses is None:
            self.mac_addresses = {}
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_json(self) -> str:
        """Serialize backup data to JSON."""
        return json.dumps({
            'hostname': self.hostname,
            'hostname_file': self.hostname_file,
            'hosts_file': self.hosts_file,
            'machine_id': self.machine_id,
            'dbus_machine_id': self.dbus_machine_id,
            'timezone': self.timezone,
            'mac_addresses': self.mac_addresses,
            'timestamp': self.timestamp
        }, indent=2)

    @classmethod
    def from_json(cls, data: str) -> 'BackupData':
        """Deserialize backup data from JSON."""
        obj = json.loads(data)
        return cls(**obj)


class SystemCommandExecutor:
    """Handles execution of system commands with error handling."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def run(self, command: List[str], check: bool = True) -> Tuple[int, str, str]:
        """
        Execute a system command.

        Args:
            command: Command as list of strings
            check: Raise exception on non-zero exit code

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            RuntimeError: If command fails and check=True
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )

            if check and result.returncode != 0:
                error_msg = f"Command failed: {' '.join(command)}\n{result.stderr}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            return result.returncode, result.stdout.strip(), result.stderr.strip()

        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Command timeout: {' '.join(command)}")
            raise RuntimeError(f"Command timeout: {' '.join(command)}") from e
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            raise


class HostnameManager:
    """Manages hostname configuration and spoofing."""

    ADJECTIVES = ['corporate', 'enterprise', 'business', 'secure', 'trusted',
                  'reliable', 'managed', 'admin', 'cloud', 'data']
    NOUNS = ['server', 'workstation', 'laptop', 'desktop', 'system', 'node',
             'client', 'host', 'endpoint', 'instance']
    DEPARTMENTS = ['IT', 'HR', 'Finance', 'Sales', 'Marketing', 'Legal',
                   'Ops', 'DevOps', 'Infra', 'Sec']

    def __init__(self, executor: SystemCommandExecutor, logger: logging.Logger):
        self.executor = executor
        self.logger = logger

    def backup(self) -> BackupData:
        """Backup current hostname configuration."""
        self.logger.info("Backing up hostname configuration")
        backup = BackupData()

        try:
            backup.hostname = self._read_hostname()
            backup.hostname_file = Path('/etc/hostname').read_text(encoding='utf-8').strip()
            backup.hosts_file = Path('/etc/hosts').read_text(encoding='utf-8')
            self.logger.debug(f"Backed up hostname: {backup.hostname}")
        except Exception as e:
            self.logger.error(f"Hostname backup failed: {e}")
            raise

        return backup

    def spoof(self) -> str:
        """Generate and apply a random corporate hostname."""
        self.logger.info("Spoofing hostname")

        # Generate random hostname
        adj = random.choice(self.ADJECTIVES)
        noun = random.choice(self.NOUNS)
        num = random.randint(1000, 9999)
        new_hostname = f"{adj}-{noun}-{num}".lower()

        try:
            Path('/etc/hostname').write_text(f"{new_hostname}\n", encoding='utf-8')
            self.logger.debug("Updated /etc/hostname")

            self._update_hosts_file(new_hostname)
            self.logger.debug("Updated /etc/hosts")

            # Apply hostname
            self.executor.run(['hostnamectl', 'set-hostname', new_hostname])
            self.logger.info(f"✓ Hostname changed to: {new_hostname}")

            return new_hostname

        except Exception as e:
            self.logger.error(f"Hostname spoof failed: {e}")
            raise

    def restore(self, backup: BackupData) -> bool:
        """Restore original hostname configuration."""
        self.logger.info("Restoring original hostname")

        if not backup.hostname:
            self.logger.warning("No hostname backup available")
            return False

        try:
            Path('/etc/hostname').write_text(f"{backup.hostname}\n", encoding='utf-8')
            Path('/etc/hosts').write_text(backup.hosts_file, encoding='utf-8')
            self.executor.run(['hostnamectl', 'set-hostname', backup.hostname])
            self.logger.info(f"✓ Hostname restored to: {backup.hostname}")
            return True

        except Exception as e:
            self.logger.error(f"Hostname restore failed: {e}")
            return False

    def _read_hostname(self) -> str:
        """Read current hostname from system."""
        _, hostname, _ = self.executor.run(['hostnamectl', '--static'])
        return hostname

    def _update_hosts_file(self, hostname: str) -> None:
        """Update /etc/hosts with new hostname."""
        hosts_path = Path('/etc/hosts')
        content = hosts_path.read_text(encoding='utf-8')

        # Replace or add 127.0.1.1 entry
        lines = content.split('\n')
        updated_lines = []

        for line in lines:
            if line.startswith('127.0.1.1'):
                updated_lines.append(f"127.0.1.1\t{hostname}")
            else:
                updated_lines.append(line)

        hosts_path.write_text('\n'.join(updated_lines), encoding='utf-8')


class MACManager:
    """Manages MAC address spoofing and restoration."""

    # OUI Database: Vendor Name -> MAC Prefix (24-bit)
    OUI_DATABASE = {
        'Dell': ['00:14:22', '00:1F:29', '00:25:B5', '08:00:06', '40:B0:34'],
        'HP/Hewlett-Packard': ['00:13:21', '00:16:35', '00:1B:21', 'EC:F4:BB', '50:E5:49'],
        'Lenovo': ['54:BF:64', '00:21:28', '00:1C:42', '28:16:AD', '00:19:21'],
        'Asus': ['3C:52:82', '00:14:32', '08:11:96', '00:19:CB', '08:60:6E'],
        'Intel': ['00:1C:23', '00:0B:0D', '00:1E:0B', '00:1A:6B', '54:E1:AD'],
        'Apple': ['00:03:93', '00:05:02', '00:14:51', '00:16:CB', '00:19:E3'],
        'Microsoft': ['00:E0:4C', '00:B0:D0', '52:54:00', '00:15:5D', '00:55:DA'],
        'Google': ['00:1A:11', '52:54:00', '00:26:55', '88:18:56', '00:24:BE'],
        'Amazon': ['52:54:00', '0A:18:D6', '02:42:AC', '00:50:F2', '00:0C:29'],
        'Cisco': ['00:00:0C', '00:01:42', '00:02:4A', '00:03:6B', '00:04:9F'],
        'Broadcom': ['00:10:18', '00:0F:AC', '00:11:20', '00:13:10', '00:15:6D'],
        'Qualcomm': ['00:04:75', '00:11:5B', '00:18:8B', '00:1D:E0', '00:1F:64'],
        'Arista': ['00:1C:73', '08:00:27', '52:40:00', '00:50:56', '00:0C:29'],
        'Ubiquiti': ['00:15:6D', '00:27:22', '74:AC:B9', '08:55:31', '00:25:86'],
    }

    VENDOR_PREFIXES = [
        '00:14:22',  # Dell
        'EC:F4:BB',  # HP
        '54:BF:64',  # Lenovo
        '3C:52:82',  # Asus
        '00:1C:23',  # Intel
        '08:00:27',  # VirtualBox
    ]

    def __init__(self, executor: SystemCommandExecutor, logger: logging.Logger):
        self.executor = executor
        self.logger = logger
        self._ensure_macchanger()

    def _ensure_macchanger(self) -> None:
        """Ensure macchanger is installed."""
        try:
            self.executor.run(['which', 'macchanger'], check=True)
            self.logger.debug("macchanger found")
        except RuntimeError:
            self.logger.warning("macchanger not found, installing...")
            try:
                self.executor.run(['apt-get', 'update', '-qq'])
                self.executor.run(['apt-get', 'install', '-y', 'macchanger'])
                self.logger.info("✓ macchanger installed")
            except RuntimeError as e:
                self.logger.error(f"Failed to install macchanger: {e}")
                raise

    def backup(self) -> Dict[str, str]:
        """Backup current MAC addresses."""
        self.logger.info("Backing up MAC addresses")
        macs = {}

        try:
            interfaces = self._get_interfaces()
            for iface in interfaces:
                mac = self._get_mac_address(iface)
                if mac:
                    macs[iface] = mac
                    self.logger.debug(f"Backed up {iface}: {mac}")

            return macs

        except Exception as e:
            self.logger.error(f"MAC backup failed: {e}")
            raise

    def spoof(self) -> Dict[str, str]:
        """Spoof all network interface MAC addresses."""
        self.logger.info("Spoofing MAC addresses")
        interfaces = self._get_interfaces()
        spoofed_macs = {}

        for iface in interfaces:
            try:
                self.logger.debug(f"Spoofing {iface}")

                # Bring interface down
                self.executor.run(['ip', 'link', 'set', iface, 'down'])

                # Generate random MAC
                vendor = random.choice(self.VENDOR_PREFIXES)
                octets = [f"{random.randint(0, 255):02x}" for _ in range(3)]
                new_mac = f"{vendor}:{':'.join(octets)}"

                # Apply MAC
                self.executor.run(['ip', 'link', 'set', 'dev', iface,
                                  'address', new_mac])

                # Bring interface back up
                self.executor.run(['ip', 'link', 'set', iface, 'up'])

                spoofed_macs[iface] = new_mac
                self.logger.info(f"✓ {iface} MAC changed to: {new_mac}")

            except Exception as e:
                self.logger.error(f"MAC spoof failed for {iface}: {e}")
                continue

        self._restart_networking()
        return spoofed_macs

    def restore(self, backup: Dict[str, str]) -> bool:
        """Restore original MAC addresses."""
        self.logger.info("Restoring MAC addresses")

        if not backup:
            self.logger.warning("No MAC backup available")
            return False

        success_count = 0

        for iface, mac in backup.items():
            try:
                self.logger.debug(f"Restoring {iface} to {mac}")

                self.executor.run(['ip', 'link', 'set', iface, 'down'])
                self.executor.run(['ip', 'link', 'set', 'dev', iface,
                                  'address', mac])
                self.executor.run(['ip', 'link', 'set', iface, 'up'])

                success_count += 1
                self.logger.info(f"✓ {iface} MAC restored")

            except Exception as e:
                self.logger.error(f"MAC restore failed for {iface}: {e}")

        self._restart_networking()
        return success_count == len(backup)

    def _get_interfaces(self) -> List[str]:
        """Get list of network interfaces (excluding loopback)."""
        _, output, _ = self.executor.run(['ip', 'link', 'show'])

        interfaces = []
        for line in output.split('\n'):
            if line and line[0].isdigit():
                parts = line.split(':')
                if len(parts) >= 2:
                    iface = parts[1].strip()
                    if iface != 'lo':
                        interfaces.append(iface)

        self.logger.debug(f"Found interfaces: {interfaces}")
        return interfaces

    def _get_mac_address(self, interface: str) -> Optional[str]:
        """Get current MAC address for interface."""
        try:
            _, output, _ = self.executor.run(['ip', 'link', 'show', interface])

            for line in output.split('\n'):
                if 'link/ether' in line:
                    parts = line.split()
                    # Format: "link/ether XX:XX:XX:XX:XX:XX brd ..."
                    if len(parts) >= 2:
                        return parts[1]

            return None

        except Exception as e:
            self.logger.error(f"Failed to get MAC for {interface}: {e}")
            return None

    def _restart_networking(self) -> None:
        """Restart networking services."""
        services = ['NetworkManager', 'networking', 'systemd-networkd']

        for service in services:
            try:
                self.executor.run(['systemctl', 'restart', service], check=False)
                self.logger.debug(f"Restarted {service}")
                break
            except Exception:
                continue

    def get_available_vendors(self) -> List[str]:
        """Get list of available vendors."""
        return sorted(list(self.OUI_DATABASE.keys()))

    def generate_macs_for_vendor(self, vendor: str, count: int = 5) -> List[str]:
        """Generate multiple realistic MAC addresses for specific vendor."""
        if vendor not in self.OUI_DATABASE:
            self.logger.warning("Vendor not found: %s, using random prefixes", vendor)
            vendor_prefixes = self.VENDOR_PREFIXES
        else:
            vendor_prefixes = self.OUI_DATABASE[vendor]

        macs = []
        for _ in range(count):
            prefix = random.choice(vendor_prefixes)
            octets = [f"{random.randint(0, 255):02x}" for _ in range(3)]
            mac = f"{prefix}:{':'.join(octets)}"
            macs.append(mac)
        return macs

    def generate_mac_from_vendor(self, vendor: str) -> str:
        """Generate single MAC address from specific vendor."""
        macs = self.generate_macs_for_vendor(vendor, count=1)
        return macs[0] if macs else "00:00:00:00:00:00"

    def spoof_with_vendor(self, vendor: str) -> Dict[str, str]:
        """Spoof all interfaces with specific vendor MAC."""
        self.logger.info("Spoofing MAC addresses with vendor: %s", vendor)
        interfaces = self._get_interfaces()
        spoofed_macs = {}

        for iface in interfaces:
            try:
                self.logger.debug("Spoofing %s", iface)

                # Bring interface down
                self.executor.run(['ip', 'link', 'set', iface, 'down'])

                # Generate MAC from vendor
                new_mac = self.generate_mac_from_vendor(vendor)

                # Apply MAC
                self.executor.run(['ip', 'link', 'set', 'dev', iface,
                                  'address', new_mac])

                # Bring interface back up
                self.executor.run(['ip', 'link', 'set', iface, 'up'])

                spoofed_macs[iface] = new_mac
                self.logger.info("✓ %s MAC changed to: %s (%s)", iface, new_mac, vendor)

            except Exception as e:
                self.logger.error("MAC spoof failed for %s: %s", iface, e)
                continue

        self._restart_networking()
        return spoofed_macs


class MachineIDManager:
    """Manages machine ID and DBUS ID spoofing."""

    def __init__(self, executor: SystemCommandExecutor, logger: logging.Logger):
        self.executor = executor
        self.logger = logger

    def backup(self) -> BackupData:
        """Backup current machine IDs."""
        self.logger.info("Backing up machine IDs")
        backup = BackupData()

        try:
            machine_id_path = Path('/etc/machine-id')
            if machine_id_path.exists():
                backup.machine_id = machine_id_path.read_text().strip()

            dbus_id_path = Path('/var/lib/dbus/machine-id')
            if dbus_id_path.exists():
                backup.dbus_machine_id = dbus_id_path.read_text().strip()

            self.logger.debug("Machine IDs backed up")

        except Exception as e:
            self.logger.error(f"Machine ID backup failed: {e}")
            raise

        return backup

    def spoof(self) -> str:
        """Generate and apply new machine IDs."""
        self.logger.info("Spoofing machine IDs")

        try:
            # Generate new ID (32 hex chars)
            new_id = os.urandom(16).hex()

            # Update /etc/machine-id
            Path('/etc/machine-id').write_text(f"{new_id}\n", encoding='utf-8')
            self.logger.debug("Updated /etc/machine-id")

            # Update /var/lib/dbus/machine-id
            dbus_path = Path('/var/lib/dbus/machine-id')
            dbus_path.write_text(f"{new_id}\n", encoding='utf-8')
            self.logger.debug("Updated /var/lib/dbus/machine-id")

            self.logger.info(f"✓ Machine ID changed to: {new_id}")
            return new_id

        except Exception as e:
            self.logger.error(f"Machine ID spoof failed: {e}")
            raise

    def restore(self, backup: BackupData) -> bool:
        """Restore original machine IDs."""
        self.logger.info("Restoring machine IDs")

        try:
            if backup.machine_id:
                Path('/etc/machine-id').write_text(f"{backup.machine_id}\n", encoding='utf-8')

            if backup.dbus_machine_id:
                Path('/var/lib/dbus/machine-id').write_text(
                    f"{backup.dbus_machine_id}\n", encoding='utf-8'
                )

            self.logger.info("✓ Machine IDs restored")
            return True

        except Exception as e:
            self.logger.error(f"Machine ID restore failed: {e}")
            return False


class TimezoneManager:
    """Manages timezone spoofing and restoration."""

    TIMEZONES = [
        'America/New_York',
        'America/Chicago',
        'America/Denver',
        'America/Los_Angeles',
        'Europe/London',
        'Europe/Paris',
        'Europe/Berlin',
        'Asia/Tokyo',
        'Australia/Sydney',
        'Asia/Singapore',
        'Europe/Amsterdam',
        'America/Toronto',
    ]

    def __init__(self, executor: SystemCommandExecutor, logger: logging.Logger):
        self.executor = executor
        self.logger = logger

    def backup(self) -> str:
        """Backup current timezone."""
        self.logger.info("Backing up timezone")

        try:
            _, tz, _ = self.executor.run(
                ['timedatectl', 'show', '--property=Timezone', '--value']
            )
            self.logger.debug(f"Backed up timezone: {tz}")
            return tz

        except Exception as e:
            self.logger.error(f"Timezone backup failed: {e}")
            raise

    def spoof(self) -> str:
        """Spoof timezone to random corporate timezone."""
        self.logger.info("Spoofing timezone")

        try:
            new_tz = random.choice(self.TIMEZONES)
            self.executor.run(['timedatectl', 'set-timezone', new_tz])
            self.logger.info(f"✓ Timezone changed to: {new_tz}")
            return new_tz

        except Exception as e:
            self.logger.error(f"Timezone spoof failed: {e}")
            raise

    def spoof_timezone(self, timezone: str) -> str:
        """Spoof timezone to specific timezone."""
        self.logger.info("Spoofing timezone to: %s", timezone)

        try:
            self.executor.run(['timedatectl', 'set-timezone', timezone])
            self.logger.info(f"✓ Timezone changed to: {timezone}")
            return timezone

        except Exception as e:
            self.logger.error(f"Timezone spoof failed: {e}")
            raise

    def restore(self, backup: str) -> bool:
        """Restore original timezone."""
        self.logger.info("Restoring timezone")

        if not backup:
            self.logger.warning("No timezone backup available")
            return False

        try:
            self.executor.run(['timedatectl', 'set-timezone', backup])
            self.logger.info(f"✓ Timezone restored to: {backup}")
            return True

        except Exception as e:
            self.logger.error(f"Timezone restore failed: {e}")
            return False


class ForensicCleaner:
    """Handles clearing forensic artifacts."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def clear_all(self) -> bool:
        """Clear all forensic artifacts."""
        self.logger.info("Clearing forensic artifacts")

        results = [
            self._clear_bash_history(),
            self._clear_system_logs(),
            self._clear_temp_files(),
            self._clear_cache(),
        ]

        success = all(results)
        if success:
            self.logger.info("✓ Forensic artifacts cleared")
        else:
            self.logger.warning("⚠ Partial artifact clearing completed")

        return success

    def _clear_bash_history(self) -> bool:
        """Clear bash history."""
        try:
            self.logger.debug("Clearing bash history")
            history_file = Path.home() / '.bash_history'
            history_file.write_text('')
            return True
        except Exception as e:
            self.logger.error(f"Failed to clear bash history: {e}")
            return False

    def _clear_system_logs(self) -> bool:
        """Clear system log files."""
        try:
            self.logger.debug("Clearing system logs")
            log_dir = Path('/var/log')

            if log_dir.exists():
                for log_file in log_dir.glob('**/*.log'):
                    try:
                        log_file.write_text('', encoding='utf-8')
                    except Exception as e:
                        self.logger.debug("Skipped %s: %s", log_file, e)

            return True

        except Exception as e:
            self.logger.error(f"Failed to clear system logs: {e}")
            return False

    def _clear_temp_files(self) -> bool:
        """Clear temporary files."""
        try:
            self.logger.debug("Clearing temp files")
            temp_dirs = [Path('/tmp'), Path('/var/tmp')]

            for temp_dir in temp_dirs:
                if temp_dir.exists():
                    for item in temp_dir.iterdir():
                        try:
                            if item.is_file():
                                item.unlink()
                            elif item.is_dir():
                                shutil.rmtree(item)
                        except Exception as e:
                            self.logger.debug("Skipped %s: %s", item, e)

            return True

        except Exception as e:
            self.logger.error("Failed to clear temp files: %s", e)
            return False

    def _clear_cache(self) -> bool:
        """Clear user cache and recent files."""
        try:
            self.logger.debug("Clearing cache")
            cache_items = [
                Path.home() / '.cache',
                Path.home() / '.local/share/recently-used.xbel',
                Path.home() / '.local/share/recently-used',
            ]

            for item in cache_items:
                try:
                    if item.exists():
                        if item.is_file():
                            item.unlink()
                        else:
                            shutil.rmtree(item)
                except Exception as e:
                    self.logger.debug("Skipped %s: %s", item, e)

            return True

        except Exception as e:
            self.logger.error(f"Failed to clear cache: {e}")
            return False


class HostOpsecManager:
    """Main orchestrator for host OPSEC operations."""

    def __init__(self, backup_dir: str = '/root/.host-opsec-backups'):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.logger = self._setup_logging()
        self.executor = SystemCommandExecutor(self.logger)
        self.api = APIHelper(self.logger)

        # Initialize managers
        self.hostname_mgr = HostnameManager(self.executor, self.logger)
        self.mac_mgr = MACManager(self.executor, self.logger)
        self.machine_id_mgr = MachineIDManager(self.executor, self.logger)
        self.timezone_mgr = TimezoneManager(self.executor, self.logger)
        self.forensic_cleaner = ForensicCleaner(self.logger)

    def _setup_logging(self) -> logging.Logger:
        """Configure logging."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # File handler
        log_file = self.backup_dir / 'host-opsec.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    def get_backup_file(self) -> Path:
        """Get backup file path."""
        return self.backup_dir / 'backup.json'

    def _save_backup(self, backup: BackupData) -> None:
        """Save backup to file."""
        backup_file = self.get_backup_file()
        backup_file.write_text(backup.to_json())
        self.logger.info(f"Backup saved to: {backup_file}")

    def _load_backup(self) -> Optional[BackupData]:
        """Load backup from file."""
        backup_file = self.get_backup_file()

        if not backup_file.exists():
            self.logger.warning("No backup file found")
            return None

        try:
            data = backup_file.read_text()
            backup = BackupData.from_json(data)
            self.logger.info(f"Backup loaded from: {backup_file}")
            return backup
        except Exception as e:
            self.logger.error(f"Failed to load backup: {e}")
            return None

    def spoof_all(self) -> bool:
        """Execute full spoofing of all identifiers."""
        self.logger.info("=" * 60)
        self.logger.info("STARTING FULL HOST SPOOFING")
        self.logger.info("=" * 60)

        backup = BackupData()

        try:
            # Backup hostname
            hostname_backup = self.hostname_mgr.backup()
            backup.hostname = hostname_backup.hostname
            backup.hostname_file = hostname_backup.hostname_file
            backup.hosts_file = hostname_backup.hosts_file

            # Backup MACs
            mac_backup = self.mac_mgr.backup()
            backup.mac_addresses = mac_backup

            # Backup machine ID
            machine_id_backup = self.machine_id_mgr.backup()
            backup.machine_id = machine_id_backup.machine_id
            backup.dbus_machine_id = machine_id_backup.dbus_machine_id

            # Backup timezone
            backup.timezone = self.timezone_mgr.backup()

            # Spoof
            self.hostname_mgr.spoof()
            self.mac_mgr.spoof()
            self.machine_id_mgr.spoof()
            self.timezone_mgr.spoof()

            # Save backup
            self._save_backup(backup)

            self.logger.info("=" * 60)
            self.logger.info("✓ FULL SPOOFING COMPLETE")
            self.logger.info("=" * 60)
            return True

        except Exception as e:
            self.logger.error("Spoofing failed: %s", e)
            return False

    def restore_all(self) -> bool:
        """Restore all original values."""
        self.logger.info("=" * 60)
        self.logger.info("STARTING RESTORATION")
        self.logger.info("=" * 60)

        backup = self._load_backup()

        if not backup:
            self.logger.error("No backup available for restoration")
            return False

        results = [
            self.hostname_mgr.restore(backup),
            self.mac_mgr.restore(backup.mac_addresses),
            self.machine_id_mgr.restore(backup),
            self.timezone_mgr.restore(backup.timezone),
        ]

        success = all(results)

        if success:
            self.logger.info("=" * 60)
            self.logger.info("✓ RESTORATION COMPLETE")
            self.logger.info("=" * 60)
        else:
            self.logger.warning("⚠ PARTIAL RESTORATION COMPLETED")

        return success

    def show_status(self) -> None:
        """Display current system status."""
        self.logger.info("=" * 60)
        self.logger.info("CURRENT SYSTEM STATUS")
        self.logger.info("=" * 60)

        try:
            # Hostname
            self.logger.info("\n[*] Hostname:")
            _, hostname, _ = self.executor.run(['hostname'])
            self.logger.info(f"    {hostname}")

            # MAC Addresses
            self.logger.info("\n[*] MAC Addresses:")
            _, output, _ = self.executor.run(['ip', 'link', 'show'])
            for line in output.split('\n'):
                if 'link/ether' in line:
                    self.logger.info(f"    {line.strip()}")

            # Machine ID
            self.logger.info("\n[*] Machine ID:")
            try:
                machine_id = Path('/etc/machine-id').read_text().strip()
                self.logger.info(f"    {machine_id}")
            except Exception:
                self.logger.info("    N/A")

            # Timezone
            self.logger.info("\n[*] Timezone:")
            _, tz, _ = self.executor.run(
                ['timedatectl', 'show', '--property=Timezone', '--value']
            )
            self.logger.info(f"    {tz}")

            self.logger.info("\n" + "=" * 60)

        except Exception as e:
            self.logger.error(f"Failed to retrieve status: {e}")

    def clear_artifacts(self) -> bool:
        """Clear forensic artifacts."""
        return self.forensic_cleaner.clear_all()


class InteractiveMenu:
    """Interactive dashboard menu for HOST-OPSEC."""

    # ANSI Color codes for red team aesthetic
    RED = '\033[91m'
    DARK_RED = '\033[31m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_BLACK = '\033[40m'

    def __init__(self, manager: HostOpsecManager):
        self.manager = manager

    def clear_screen(self) -> None:
        """Clear terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def print_header(self) -> None:
        """Print application header with red team styling."""
        header = f"""
{self.RED}{self.BOLD}{'=' * 70}{self.RESET}
{self.RED}{self.BOLD}  🔒 HOESEC Red Team Host-Level OPSEC Automation{self.RESET}
{self.RED}{self.BOLD}{'=' * 70}{self.RESET}
"""
        print(header)

    def get_current_stats(self) -> Dict[str, str]:
        """Get current system stats for dashboard display."""
        stats = {}

        # Hostname
        try:
            _, hostname, _ = self.manager.executor.run(['hostname'])
            stats['hostname'] = hostname
        except Exception:
            stats['hostname'] = 'N/A'

        # MAC count
        try:
            _, output, _ = self.manager.executor.run(['ip', 'link', 'show'])
            mac_count = sum(1 for line in output.split('\n') if 'link/ether' in line)
            stats['mac_count'] = str(mac_count)
        except Exception:
            stats['mac_count'] = '0'

        # Machine ID (first 8 chars)
        try:
            machine_id = Path('/etc/machine-id').read_text(encoding='utf-8').strip()
            stats['machine_id'] = machine_id[:8]
        except Exception:
            stats['machine_id'] = 'N/A'

        # Timezone
        try:
            _, tz, _ = self.manager.executor.run(
                ['timedatectl', 'show', '--property=Timezone', '--value']
            )
            stats['timezone'] = tz
        except Exception:
            stats['timezone'] = 'N/A'

        # Backup status
        stats['backup'] = '✓' if self.manager.get_backup_file().exists() else '✗'

        return stats

    def print_menu(self) -> None:
        """Display main menu options with system status."""
        self.clear_screen()
        self.print_header()

        # Get and display current system stats
        stats = self.get_current_stats()

        # System status banner
        status_line = f"""
{self.CYAN}{self.BOLD}[*] SYSTEM STATUS{self.RESET}
{self.DARK_RED}{'─' * 70}{self.RESET}
{self.CYAN}Hostname:{self.RESET} {self.BOLD}{stats['hostname']}{self.RESET}  │  \
{self.CYAN}MACs:{self.RESET} {self.BOLD}{stats['mac_count']}{self.RESET}  │  \
{self.CYAN}Machine ID:{self.RESET} {self.BOLD}{stats['machine_id']}{self.RESET}  │  \
{self.CYAN}Timezone:{self.RESET} {self.BOLD}{stats['timezone']}{self.RESET}
{self.CYAN}Backup:{self.RESET} {self.GREEN if stats['backup'] == '✓' else self.RED}{self.BOLD}{stats['backup']}{self.RESET}
{self.DARK_RED}{'─' * 70}{self.RESET}
"""
        print(status_line)

        # noqa: E501
        menu_str = f"""
{self.RED}{self.BOLD}┌─────────────────────────────────────────────────────────────┐{self.RESET}
{self.RED}{self.BOLD}│{self.RESET} {self.CYAN}SPOOFING OPERATIONS{self.RESET}{' ' * 40} {self.RED}{self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}├─────────────────────────────────────────────────────────────┤{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[1]{self.RESET} Spoof ALL (Hostname + MAC + Machine ID + Timezone)     {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[2]{self.RESET} Spoof Hostname only                                    {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.YELLOW}[3]{self.RESET} Spoof MAC Addresses only                               {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[4]{self.RESET} Spoof Machine ID only                                  {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.CYAN}[5]{self.RESET} Spoof Timezone only                                    {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}                                                             {self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}├─────────────────────────────────────────────────────────────┤{self.RESET}
{self.RED}{self.BOLD}│{self.RESET} {self.CYAN}RESTORATION OPERATIONS{self.RESET}{' ' * 37} {self.RED}{self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}├─────────────────────────────────────────────────────────────┤{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[6]{self.RESET} Restore ALL from backup                                {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[7]{self.RESET} Restore Hostname only                                  {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.YELLOW}[8]{self.RESET} Restore MAC Addresses only                             {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.GREEN}[9]{self.RESET} Restore Machine ID only                                {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.CYAN}[10]{self.RESET} Restore Timezone only                                 {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}                                                             {self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}├─────────────────────────────────────────────────────────────┤{self.RESET}
{self.RED}{self.BOLD}│{self.RESET} {self.CYAN}UTILITY OPERATIONS{self.RESET}{' ' * 42}{self.RED}{self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}├─────────────────────────────────────────────────────────────┤{self.RESET}
{self.BOLD}│{self.RESET}  {self.BLUE}[11]{self.RESET} View System Status                                    {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.BLUE}[12]{self.RESET} Clear Forensic Artifacts                              {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.BLUE}[13]{self.RESET} View Logs                                             {self.BOLD}│{self.RESET}
{self.BOLD}│{self.RESET}  {self.RED}[0]{self.RESET} Exit                                                   {self.BOLD}│{self.RESET}
{self.RED}{self.BOLD}└─────────────────────────────────────────────────────────────┘{self.RESET} 
"""
        print(menu_str)

    def show_status(self) -> None:
        """Display current system status."""
        self.clear_screen()
        self.print_header()

        try:
            print("📊 CURRENT SYSTEM CONFIGURATION\n")

            # Hostname
            try:
                _, hostname, _ = self.manager.executor.run(['hostname'])
                print(f"  🖥️  Hostname: {hostname}")
            except Exception:
                print("  🖥️  Hostname: [Error reading]")

            # MAC Addresses
            print("\n  🔗 MAC Addresses:")
            try:
                _, output, _ = self.manager.executor.run(['ip', 'link', 'show'])
                mac_count = 0
                for line in output.split('\n'):
                    if 'link/ether' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            print(f"      • {parts[1]}")
                            mac_count += 1
                if mac_count == 0:
                    print("      [No MACs found]")
            except Exception:
                print("      [Error reading]")

            # Machine ID
            try:
                machine_id = Path('/etc/machine-id').read_text(encoding='utf-8').strip()
                print(f"\n  🔐 Machine ID: {machine_id[:16]}...")
            except Exception:
                print("\n  🔐 Machine ID: [Not readable]")

            # Timezone
            try:
                _, tz, _ = self.manager.executor.run(
                    ['timedatectl', 'show', '--property=Timezone', '--value']
                )
                print(f"  🌍 Timezone: {tz}")
            except Exception:
                print("  🌍 Timezone: [Error reading]")

            # Backup Info
            backup_file = self.manager.get_backup_file()
            if backup_file.exists():
                timestamp = Path(backup_file).stat().st_mtime
                backup_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"\n  💾 Last Backup: {backup_time}")
            else:
                print("\n  💾 Last Backup: None")

            print("\n" + "=" * 70)

        except Exception as e:
            print(f"\n❌ Error retrieving status: {e}\n")

        input("Press Enter to return to menu...")

    def view_logs(self) -> None:
        """Display recent logs."""
        self.clear_screen()
        self.print_header()

        log_file = self.manager.backup_dir / 'host-opsec.log'

        if not log_file.exists():
            print("❌ No logs found yet.\n")
            input("Press Enter to return to menu...")
            return

        try:
            logs = log_file.read_text()
            lines = logs.split('\n')

            # Show last 30 lines
            recent_logs = lines[-30:] if len(lines) > 30 else lines

            print("📜 RECENT LOGS (Last 30 entries):\n")
            for line in recent_logs:
                if line:
                    print(f"  {line}")

            print("\n" + "=" * 70)

        except Exception as e:
            print(f"❌ Error reading logs: {e}\n")

        input("Press Enter to return to menu...")

    def execute_operation(self, choice: str) -> None:
        """Execute selected operation."""
        self.clear_screen()
        self.print_header()

        try:
            if choice == '1':
                print("🚀 Spoofing ALL components...\n")
                self.manager.spoof_all()
                print("\n✅ Spoof ALL completed!")

            elif choice == '2':
                print("🚀 Spoofing Hostname...\n")
                self.manager.hostname_mgr.spoof()
                print("\n✅ Hostname spoof completed!")

            elif choice == '3':
                print("🚀 Spoofing MAC Addresses...\n")

                # Step 1: Select Vendor
                vendors = self.manager.mac_mgr.get_available_vendors()
                print(f"Available vendors: {len(vendors)} total\n")
                for idx, vendor in enumerate(vendors, 1):
                    print(f"  [{idx}] {vendor}")
                print("  [0] Random (skip vendor selection)\n")

                try:
                    vendor_idx = int(input("Select vendor [0-{}]: ".format(
                        len(vendors)))) - 1

                    if vendor_idx == -1:
                        # Random mode
                        print("\n✓ Using random vendor\n")
                        self.manager.mac_mgr.spoof()
                    elif 0 <= vendor_idx < len(vendors):
                        selected_vendor = vendors[vendor_idx]
                        print(f"\n✓ Selected vendor: {selected_vendor}\n")

                        # Step 2: Generate and show MACs for vendor
                        print("Generating realistic MACs for this vendor...\n")
                        macs = self.manager.mac_mgr.generate_macs_for_vendor(
                            selected_vendor, count=5)

                        print(f"Available MACs ({selected_vendor}):\n")
                        for idx, mac in enumerate(macs, 1):
                            print(f"  [{idx}] {mac}")
                        print("  [0] Random from this vendor\n")

                        try:
                            mac_idx = int(input(
                                "Select MAC to spoof [0-5]: ")) - 1

                            if mac_idx == -1:
                                # Use random MAC from vendor
                                print(f"\n✓ Using random MAC from {selected_vendor}\n")
                                self.manager.mac_mgr.spoof_with_vendor(
                                    selected_vendor)
                            elif 0 <= mac_idx < len(macs):
                                selected_mac = macs[mac_idx]
                                print(f"\n✓ Using MAC: {selected_mac}\n")
                                self.manager.mac_mgr.spoof_with_vendor(
                                    selected_vendor)
                            else:
                                print(
                                    "❌ Invalid MAC selection, using vendor")
                                self.manager.mac_mgr.spoof_with_vendor(
                                    selected_vendor)

                        except ValueError:
                            print(
                                "❌ Invalid input, using vendor")
                            self.manager.mac_mgr.spoof_with_vendor(
                                selected_vendor)
                    else:
                        print("❌ Invalid selection, using random")
                        self.manager.mac_mgr.spoof()

                except ValueError:
                    print("❌ Invalid input, using random vendor")
                    self.manager.mac_mgr.spoof()

                print("\n✅ MAC spoofing completed!")

            elif choice == '4':
                print("🚀 Spoofing Machine ID...\n")
                self.manager.machine_id_mgr.spoof()
                print("\n✅ Machine ID spoof completed!")

            elif choice == '5':
                print("🚀 Spoofing Timezone...\n")
                print("Choose spoofing method:")
                print("  [1] Random timezone (default)")
                print("  [2] Get timezone suggestions from API\n")
                tz_choice = input("Select option: ").strip()

                if tz_choice == '2':
                    print("\n🌍 Fetching timezone suggestions from API...\n")
                    timezones = self.manager.api.lookup_timezones_by_country()
                    if timezones:
                        print(f"Available timezones: {len(timezones)} total\n")
                        # Show first 15 options
                        for idx, tz in enumerate(timezones[:15], 1):
                            print(f"  [{idx}] {tz}")
                        if len(timezones) > 15:
                            print(f"\n  ...and {len(timezones) - 15} more\n")

                        try:
                            tz_idx = int(input("Select timezone: ")) - 1
                            if 0 <= tz_idx < len(timezones):
                                selected_tz = timezones[tz_idx]
                                print(f"\n✓ Using timezone: {selected_tz}\n")
                                self.manager.timezone_mgr.spoof_timezone(selected_tz)
                            else:
                                print("❌ Invalid selection, using random timezone")
                                self.manager.timezone_mgr.spoof()
                        except ValueError:
                            print("❌ Invalid input, using random timezone")
                            self.manager.timezone_mgr.spoof()
                    else:
                        print("⚠️  API unavailable, using random timezone")
                        self.manager.timezone_mgr.spoof()
                else:
                    self.manager.timezone_mgr.spoof()

                print("\n✅ Timezone spoof completed!")

            elif choice == '6':
                print("♻️  Restoring ALL components from backup...\n")
                success = self.manager.restore_all()
                print(f"\n{'✅ Restoration completed!' if success else '❌ Restoration failed!'}")

            elif choice == '7':
                print("♻️  Restoring Hostname...\n")
                backup = self.manager._load_backup()
                if backup:
                    self.manager.hostname_mgr.restore(backup)
                    print("\n✅ Hostname restore completed!")
                else:
                    print("\n❌ No backup available!")

            elif choice == '8':
                print("♻️  Restoring MAC Addresses...\n")
                backup = self.manager._load_backup()
                if backup and backup.mac_addresses:
                    self.manager.mac_mgr.restore(backup.mac_addresses)
                    print("\n✅ MAC restore completed!")
                else:
                    print("\n❌ No MAC backup available!")

            elif choice == '9':
                print("♻️  Restoring Machine ID...\n")
                backup = self.manager._load_backup()
                if backup:
                    self.manager.machine_id_mgr.restore(backup)
                    print("\n✅ Machine ID restore completed!")
                else:
                    print("\n❌ No backup available!")

            elif choice == '10':
                print("♻️  Restoring Timezone...\n")
                backup = self.manager._load_backup()
                if backup and backup.timezone:
                    self.manager.timezone_mgr.restore(backup.timezone)
                    print("\n✅ Timezone restore completed!")
                else:
                    print("\n❌ No timezone backup available!")

            elif choice == '11':
                self.show_status()
                return

            elif choice == '12':
                print("🧹 Clearing forensic artifacts...\n")
                print("  [!] This operation will clear:")
                print("      • Bash history")
                print("      • System logs")
                print("      • Temporary files")
                print("      • Cache files\n")

                confirm = input("⚠️  Are you sure? (yes/no): ").lower()
                if confirm == 'yes':
                    self.manager.clear_artifacts()
                    print("\n✅ Artifacts cleared!")
                else:
                    print("\n⏭️  Operation cancelled!")

                input("\nPress Enter to return to menu...")
                return

            elif choice == '13':
                self.view_logs()
                return

            elif choice == '0':
                self.clear_screen()
                print("\n👋 Exiting HOST-OPSEC Dashboard...\n")
                sys.exit(0)

            else:
                print("❌ Invalid choice. Please try again.")

            input("\nPress Enter to return to menu...")

        except Exception as e:
            print(f"\n❌ Operation failed: {e}\n")
            input("Press Enter to return to menu...")

    def run(self) -> None:
        """Run interactive menu loop."""
        while True:
            self.print_menu()
            choice = input("Select option: ").strip()
            self.execute_operation(choice)


def check_root() -> bool:
    """Check if script is running as root."""
    return os.geteuid() == 0


def main() -> int:
    """Main entry point - supports interactive menu or CLI mode."""
    # Check root
    if not check_root():
        print("❌ Please run as root (use: sudo)")
        return OperationStatus.REQUIRES_ROOT.value

    # If no arguments provided, launch interactive dashboard
    if len(sys.argv) == 1:
        manager = HostOpsecManager()
        menu = InteractiveMenu(manager)
        menu.run()
        return OperationStatus.SUCCESS.value

    # Otherwise, use traditional CLI mode
    parser = argparse.ArgumentParser(
        description='HOST-OPSEC - Red Team Host-Level OPSEC Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 host_opsec_tool.py spoof-all
  sudo python3 host_opsec_tool.py status
  sudo python3 host_opsec_tool.py restore-all
  sudo python3 host_opsec_tool.py --interactive (or just: sudo python3 host_opsec_tool.py)
        """
    )

    parser.add_argument(
        'action',
        nargs='?',
        choices=[
            'spoof-all', 'restore-all', 'status', 'clear-artifacts',
            'spoof-hostname', 'restore-hostname',
            'spoof-mac', 'restore-mac',
            'spoof-machine-id', 'restore-machine-id',
            'spoof-timezone', 'restore-timezone',
        ],
        help='Action to perform'
    )

    parser.add_argument(
        '--backup-dir',
        default='/root/.host-opsec-backups',
        help='Directory for backups (default: /root/.host-opsec-backups)'
    )

    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Launch interactive dashboard'
    )

    args = parser.parse_args()

    # Launch interactive mode if requested
    if args.interactive:
        manager = HostOpsecManager(args.backup_dir)
        menu = InteractiveMenu(manager)
        menu.run()
        return OperationStatus.SUCCESS.value

    # CLI mode
    if not args.action:
        parser.print_help()
        return OperationStatus.FAILURE.value

    # Initialize manager
    manager = HostOpsecManager(args.backup_dir)

    # Execute action
    try:
        success = False
        if args.action == 'spoof-all':
            success = manager.spoof_all()
        elif args.action == 'restore-all':
            success = manager.restore_all()
        elif args.action == 'status':
            manager.show_status()
            success = True
        elif args.action == 'clear-artifacts':
            success = manager.clear_artifacts()
        elif args.action == 'spoof-hostname':
            manager.hostname_mgr.spoof()
            success = True
        elif args.action == 'restore-hostname':
            backup = manager._load_backup()
            success = manager.hostname_mgr.restore(backup) if backup else False
        elif args.action == 'spoof-mac':
            manager.mac_mgr.spoof()
            success = True
        elif args.action == 'restore-mac':
            backup = manager._load_backup()
            success = manager.mac_mgr.restore(backup.mac_addresses) if backup else False
        elif args.action == 'spoof-machine-id':
            manager.machine_id_mgr.spoof()
            success = True
        elif args.action == 'restore-machine-id':
            backup = manager._load_backup()
            success = manager.machine_id_mgr.restore(backup) if backup else False
        elif args.action == 'spoof-timezone':
            manager.timezone_mgr.spoof()
            success = True
        elif args.action == 'restore-timezone':
            backup = manager._load_backup()
            success = manager.timezone_mgr.restore(backup.timezone) if backup else False

        return OperationStatus.SUCCESS.value if success else OperationStatus.FAILURE.value

    except Exception as e:
        manager.logger.error("Operation failed: %s", e, exc_info=True)
        return OperationStatus.FAILURE.value


if __name__ == '__main__':
    sys.exit(main())
