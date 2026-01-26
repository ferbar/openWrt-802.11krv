#!/usr/bin/env python3.11
# https://claude.ai/chat/1b2be424-79aa-4844-8e58-d62c609af64c
# sudo zypper install python3-colorama python3-paramiko
# sudo zypper install python311-paramiko python311-colorama
#!/usr/bin/env python3
"""
OpenWrt 802.11r/k/v Auto-Configuration Script
Automatically configures neighbor reports and R0KH/R1KH lists

Requirements:
  pip install paramiko colorama

Usage:
  1. Create/edit roaming-config.json
  2. Set "dry_run": true for testing
  3. Run: ./openwrt-roaming-setup.py
  4. Set "dry_run": false and run again to apply
"""

import paramiko
import re
import secrets
import json
import sys
import os
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ============================================================================
# Configuration Loading
# ============================================================================

def load_config(config_file: str = 'roaming-config.json') -> Dict:
    """Load configuration from JSON file"""
    
    if not os.path.exists(config_file):
        print(f"{Fore.RED}Error: Config file '{config_file}' not found!{Style.RESET_ALL}")
        print(f"\nCreate a config file with this content:")
        print(json.dumps({
            "ssid": "your-ssid",
            "mobility_domain": "beef",
            "ssh_user": "root",
            "dry_run": True,
            "ap_hosts": ["ap1", "ap2", "ap3"]
        }, indent=2))
        sys.exit(1)
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Validate required fields
        required = ['ssid', 'mobility_domain', 'ap_hosts']
        missing = [f for f in required if f not in config]
        
        if missing:
            print(f"{Fore.RED}Error: Missing required config fields: {', '.join(missing)}{Style.RESET_ALL}")
            sys.exit(1)
        
        # Set defaults
        config.setdefault('ssh_user', 'root')
        config.setdefault('dry_run', True)
        
        return config
    
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Error parsing config file: {e}{Style.RESET_ALL}")
        sys.exit(1)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class APInterface:
    """Represents a wireless AP interface"""
    phy: str
    interface: str
    mac: str
    ssid: str
    channel: int
    frequency: int
    width: int
    
    def is_24ghz(self) -> bool:
        return 2401 <= self.frequency <= 2495
    
    def is_5ghz(self) -> bool:
        return 5170 <= self.frequency <= 5835


@dataclass
class APInfo:
    """Complete information about an access point"""
    hostname: str
    interface_24: APInterface = None
    interface_5: APInterface = None


# ============================================================================
# Generic iw Parser
# ============================================================================

def get_indent(line: str) -> int:
    """Count leading spaces"""
    return len(line) - len(line.lstrip())


def parse_iw(lines: List[str], start_idx: int = 0, base_indent: int = 0) -> Tuple[Dict[str, Any], int]:
    """
    Generic recursive parser for iw command output based on indentation
    
    Returns:
        (parsed_dict, next_line_index)
    """
    result = {}
    i = start_idx
    
    while i < len(lines):
        line = lines[i]
        
        # Skip empty lines
        if not line.strip():
            i += 1
            continue
        
        current_indent = get_indent(line)
        
        # If less indented than base, we're done with this block
        if current_indent < base_indent:
            break
        
        # Only process lines at our indent level
        if current_indent > base_indent:
            i += 1
            continue
        
        stripped = line.strip()
        
        # Check if next line is more indented (nested structure)
        if i + 1 < len(lines):
            next_indent = get_indent(lines[i + 1])
            
            if next_indent > current_indent:
                # This is a parent key, parse children recursively
                key = stripped
                child_dict, next_i = parse_iw(lines, i + 1, next_indent)
                result[key] = child_dict
                i = next_i
                continue
        
        # Regular key-value line: split at first space
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            result[key] = value
        elif len(parts) == 1:
            # Key without value
            result[parts[0]] = None
        
        i += 1
    
    return result, i


def parse_channel_line(channel_str: str) -> Tuple[int, int, int]:
    """
    Parse channel line like: "11 (2462 MHz), width: 20 MHz, center1: 2462 MHz"
    
    Returns:
        (channel, frequency, width)
    """
    match = re.match(r'(\d+)\s+\((\d+)\s+MHz\).*width:\s+(\d+)', channel_str)
    if match:
        return (
            int(match.group(1)),  # channel
            int(match.group(2)),  # frequency
            int(match.group(3))   # width
        )
    return None, None, None


def parse_iw_dev(output: str) -> List[APInterface]:
    """
    Parse 'iw dev' output into structured APInterface objects
    """
    lines = output.split('\n')
    parsed, _ = parse_iw(lines)
    
    interfaces = []
    
    # Iterate through phys
    for phy_key, phy_data in parsed.items():
        if not phy_key.startswith('phy#'):
            continue
        
        phy = phy_key.split('#')[1]
        
        # Iterate through interfaces in this phy
        for iface_key, iface_data in phy_data.items():
            if not iface_key.startswith('Interface'):
                continue
            
            iface_name = iface_key.split()[1]
            
            # Check if this is an AP with SSID
            if iface_data.get('type') != 'AP' or 'ssid' not in iface_data:
                continue
            
            # Parse channel info
            channel_str = iface_data.get('channel')
            if not channel_str:
                continue
            
            channel, frequency, width = parse_channel_line(channel_str)
            if channel is None:
                continue
            
            # Create APInterface object
            interfaces.append(APInterface(
                phy=phy,
                interface=iface_name,
                mac=iface_data.get('addr'),
                ssid=iface_data.get('ssid'),
                channel=channel,
                frequency=frequency,
                width=width
            ))
    
    return interfaces


# ============================================================================
# SSH Helper
# ============================================================================

class SSHConnection:
    """Simple SSH connection wrapper"""
    
    def __init__(self, hostname: str, username: str = 'root'):
        self.hostname = hostname
        self.username = username
        self.client = None
    
    def __enter__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.client.connect(
                self.hostname,
                username=self.username,
                look_for_keys=True,
                allow_agent=True,
                timeout=10
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.hostname}: {e}")
        
        return self
    
    def __exit__(self, *args):
        if self.client:
            self.client.close()
    
    def run(self, command: str) -> str:
        """Execute command and return output"""
        stdin, stdout, stderr = self.client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        if error and 'warning' not in error.lower():
            raise Exception(f"Command failed: {error}")
        
        return output


# ============================================================================
# Neighbor Report Generation
# ============================================================================

def generate_neighbor_report(mac: str, channel: int) -> str:
    """
    Generate 802.11k neighbor report string
    
    Format: BSSID (12 hex) + BSSID Info (8 hex) + Op Class (2 hex) + Channel (2 hex) + PHY Type (2 hex) + Sub-elements
    
    Operating Class (for Europe/AT):
      - 51 (0x33 hex, decimal 81) = 2.4 GHz channels 1-13
      - 73 (0x49 hex, decimal 115) = 5 GHz channels 36-64
      - 7c (0x7c hex, decimal 124) = 5 GHz channels 149-165
    """
    mac_clean = mac.replace(':', '').lower()
    channel_hex = f"{channel:02x}"
    
    # Operating Class
    if channel <= 14:
        op_class = "51"  # 2.4 GHz
    elif channel >= 36 and channel <= 64:
        op_class = "73"  # 5 GHz lower
    elif channel >= 100 and channel <= 144:
        op_class = "73"  # 5 GHz middle
    elif channel >= 149:
        op_class = "7c"  # 5 GHz upper
    else:
        op_class = "51"  # Fallback
    
    # BSSID Info: ff19 = reachable, same security, same authenticator, HT/VHT capable
    bssid_info = "ff190000"
    
    # PHY Type: 07 = HT (802.11n), 09 = VHT (802.11ac)
    phy_type = "07"
    
    # Sub-elements: BSS Transition Candidate Preference
    sub_elements = "030100"
    
    return f"{mac_clean}{bssid_info}{op_class}{channel_hex}{phy_type}{sub_elements}"


# ============================================================================
# Main Functions
# ============================================================================

def collect_ap_info(hostname: str, ssid: str) -> APInfo:
    """Connect to AP and collect interface information"""
    
    print(f"  Connecting to {Fore.CYAN}{hostname}{Style.RESET_ALL}...", end=" ", flush=True)
    
    try:
        with SSHConnection(hostname) as ssh:
            output = ssh.run('iw dev')
            interfaces = parse_iw_dev(output)
            
            # Filter by SSID and separate 2.4/5 GHz
            ap_info = APInfo(hostname=hostname)
            
            for iface in interfaces:
                if iface.ssid == ssid:
                    if iface.is_24ghz():
                        ap_info.interface_24 = iface
                    elif iface.is_5ghz():
                        ap_info.interface_5 = iface
            
            if not ap_info.interface_24 and not ap_info.interface_5:
                print(f"{Fore.RED}ERROR: No matching SSID found!{Style.RESET_ALL}")
                return None
            
            print(f"{Fore.GREEN}OK{Style.RESET_ALL}")
            if ap_info.interface_24:
                print(f"    2.4G: {ap_info.interface_24.mac} ch {ap_info.interface_24.channel}")
            if ap_info.interface_5:
                print(f"    5G: {ap_info.interface_5.mac} ch {ap_info.interface_5.channel}")
            
            return ap_info
    
    except ConnectionError as e:
        print(f"{Fore.RED}CONNECTION FAILED{Style.RESET_ALL}")
        print(f"    {e}")
        raise  # Re-raise to abort script
    
    except Exception as e:
        print(f"{Fore.RED}ERROR: {e}{Style.RESET_ALL}")
        raise


def ensure_package_installed(hostname: str, dry_run: bool = False) -> bool:
    """Ensure static-neighbor-report package is installed"""
    
    print(f"  Checking static-neighbor-report package...", end=" ", flush=True)
    
    try:
        with SSHConnection(hostname) as ssh:
            installed = ssh.run("opkg list-installed | grep static-neighbor-report || echo ''")
            
            if not installed.strip():
                print(f"{Fore.YELLOW}NOT INSTALLED{Style.RESET_ALL}")
                
                if dry_run:
                    print(f"    {Fore.YELLOW}[DRY RUN] Would install package{Style.RESET_ALL}")
                    return True
                else:
                    print(f"    Installing...", end=" ", flush=True)
                    ssh.run("opkg update > /dev/null 2>&1 && opkg install static-neighbor-report")
                    print(f"{Fore.GREEN}OK{Style.RESET_ALL}")
                    return True
            else:
                print(f"{Fore.GREEN}OK{Style.RESET_ALL}")
                return True
    
    except Exception as e:
        print(f"{Fore.RED}ERROR: {e}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Please install manually: opkg install static-neighbor-report{Style.RESET_ALL}")
        return False


def configure_neighbors(ap: APInfo, all_aps: List[APInfo], ssid: str, dry_run: bool = False):
    """Configure neighbor reports using static-neighbor-report package (cross-band!)"""
    
    print(f"\n{Fore.GREEN}Configuring neighbors on {ap.hostname}:{Style.RESET_ALL}")
    
    # Check/install package
    if not ensure_package_installed(ap.hostname, dry_run):
        return
    
    commands = []
    
    # Delete old neighbor entries
    commands.append("while uci -q delete static-neighbor-report.@neighbor[0]; do :; done")
    
    neighbor_count = 0
    
    # Determine which interfaces this AP has
    interfaces_on_this_ap = []
    if ap.interface_24:
        interfaces_on_this_ap.append(ap.interface_24)
    if ap.interface_5:
        interfaces_on_this_ap.append(ap.interface_5)
    
    # For each interface on this AP, add ALL other APs as neighbors (cross-band!)
    for my_iface in interfaces_on_this_ap:
        iface_name = my_iface.interface
        band_str = "2.4G" if my_iface.is_24ghz() else "5G"
        
        print(f"  Configuring {band_str} interface ({iface_name}):")
        
        # Add all other APs (both bands) as neighbors
        for other_ap in all_aps:
            if other_ap.hostname == ap.hostname:
                continue  # Skip ourselves
            
            # Add 2.4 GHz neighbor if exists
            if other_ap.interface_24:
                nr = generate_neighbor_report(
                    other_ap.interface_24.mac,
                    other_ap.interface_24.channel
                )
                
                print(f"    + {other_ap.hostname} 2.4G "
                      f"({other_ap.interface_24.mac}, ch {other_ap.interface_24.channel})")
                
                commands.extend([
                    "uci add static-neighbor-report neighbor",
                    f"uci set static-neighbor-report.@neighbor[-1].bssid='{other_ap.interface_24.mac}'",
                    f"uci set static-neighbor-report.@neighbor[-1].ssid='{ssid}'",
                    f"uci set static-neighbor-report.@neighbor[-1].neighbor_report='{nr}'",
                    f"uci set static-neighbor-report.@neighbor[-1].iface='{iface_name}'",
                    f"uci set static-neighbor-report.@neighbor[-1].disabled='0'"
                ])
                neighbor_count += 1
            
            # Add 5 GHz neighbor if exists
            if other_ap.interface_5:
                nr = generate_neighbor_report(
                    other_ap.interface_5.mac,
                    other_ap.interface_5.channel
                )
                
                print(f"    + {other_ap.hostname} 5G "
                      f"({other_ap.interface_5.mac}, ch {other_ap.interface_5.channel})")
                
                commands.extend([
                    "uci add static-neighbor-report neighbor",
                    f"uci set static-neighbor-report.@neighbor[-1].bssid='{other_ap.interface_5.mac}'",
                    f"uci set static-neighbor-report.@neighbor[-1].ssid='{ssid}'",
                    f"uci set static-neighbor-report.@neighbor[-1].neighbor_report='{nr}'",
                    f"uci set static-neighbor-report.@neighbor[-1].iface='{iface_name}'",
                    f"uci set static-neighbor-report.@neighbor[-1].disabled='0'"
                ])
                neighbor_count += 1
    
    if neighbor_count == 0:
        print(f"  {Fore.YELLOW}No neighbors to configure{Style.RESET_ALL}")
        return
    
    # Commit and restart service (with 's' at the end!)
    commands.extend([
        "uci commit static-neighbor-report",
        "/etc/init.d/static-neighbor-reports enable",
        "/etc/init.d/static-neighbor-reports restart"
    ])
    
    full_command = " && ".join(commands)
    
    if dry_run:
        print(f"\n  {Fore.YELLOW}[DRY RUN] Would execute:{Style.RESET_ALL}")
        print(f"    {commands[0]}")  # Delete old
        print(f"    ... {neighbor_count} neighbor blocks ...")
        for cmd in commands[-3:]:  # Last 3 commands
            print(f"    {cmd}")
    else:
        try:
            with SSHConnection(ap.hostname) as ssh:
                ssh.run(full_command)
            print(f"  {Fore.GREEN}✓ {neighbor_count} neighbors configured and service restarted{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")


def configure_r0kh_r1kh(ap: APInfo, all_aps: List[APInfo], 
                        mobility_domain: str, shared_secret: str, dry_run: bool = False):
    """Configure R0KH/R1KH lists for PMK R1 Push"""
    
    print(f"\n{Fore.GREEN}Configuring R0KH/R1KH on {ap.hostname}:{Style.RESET_ALL}")
    
    commands = []
    
    # Map interface to radio
    radio_24 = None
    radio_5 = None
    
    if ap.interface_24:
        radio_24 = f"default_radio{ap.interface_24.phy}"
    if ap.interface_5:
        radio_5 = f"default_radio{ap.interface_5.phy}"
    
    # Delete old R0KH/R1KH entries
    radios_to_clean = []
    if radio_24:
        radios_to_clean.append(radio_24)
    if radio_5:
        radios_to_clean.append(radio_5)
    
    for radio in radios_to_clean:
        print(f"  Cleaning {radio}...")
        commands.append(f"uci -q delete wireless.{radio}.r0kh || true")
        commands.append(f"uci -q delete wireless.{radio}.r1kh || true")
    
    # Configure for 2.4 GHz
    if ap.interface_24 and radio_24:
        print(f"  Configuring 2.4 GHz ({radio_24})")
        for other_ap in all_aps:
            if other_ap.interface_24:
                mac = other_ap.interface_24.mac
                
                # R0KH: MAC, Mobility Domain, Secret
                r0kh = f"{mac},{mobility_domain},{shared_secret}"
                
                # R1KH: MAC, R1KH-ID (= MAC with colons!), Secret
                r1kh = f"{mac},{mac},{shared_secret}"
                
                commands.append(f"uci add_list wireless.{radio_24}.r0kh='{r0kh}'")
                commands.append(f"uci add_list wireless.{radio_24}.r1kh='{r1kh}'")
    
    # Configure for 5 GHz
    if ap.interface_5 and radio_5:
        print(f"  Configuring 5 GHz ({radio_5})")
        for other_ap in all_aps:
            if other_ap.interface_5:
                mac = other_ap.interface_5.mac
                
                r0kh = f"{mac},{mobility_domain},{shared_secret}"
                r1kh = f"{mac},{mac},{shared_secret}"
                
                commands.append(f"uci add_list wireless.{radio_5}.r0kh='{r0kh}'")
                commands.append(f"uci add_list wireless.{radio_5}.r1kh='{r1kh}'")
    
    if len(commands) <= len(radios_to_clean) * 2:
        print(f"  {Fore.YELLOW}No radios to configure{Style.RESET_ALL}")
        return
    
    commands.extend(["uci commit wireless", "wifi reload"])
    full_command = " && ".join(commands)
    
    if dry_run:
        print(f"\n  {Fore.YELLOW}[DRY RUN] Would execute:{Style.RESET_ALL}")
        for cmd in commands[:4]:  # First 4 (cleaning)
            print(f"    {cmd}")
        if len(commands) > 8:
            print(f"    ... ({len(commands) - 8} more r0kh/r1kh commands) ...")
        for cmd in commands[-2:]:  # Last 2
            print(f"    {cmd}")
    else:
        try:
            with SSHConnection(ap.hostname) as ssh:
                ssh.run(full_command)
            print(f"  {Fore.GREEN}✓ R0KH/R1KH configured{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")


def verify_configuration(ap_info: APInfo):
    """Verify the configuration on an AP"""
    
    print(f"\n{Fore.GREEN}{ap_info.hostname}:{Style.RESET_ALL}")
    
    try:
        with SSHConnection(ap_info.hostname) as ssh:
            # Check static-neighbor-report config
            neighbors = ssh.run("uci show static-neighbor-report 2>/dev/null | grep '.bssid=' || true")
            if neighbors.strip():
                count = len(neighbors.strip().split('\n'))
                print(f"  Static neighbors: {count} configured")
            else:
                print(f"  {Fore.YELLOW}No static neighbors configured{Style.RESET_ALL}")
            
            # Check R0KH/R1KH
            r0kh = ssh.run("uci show wireless | grep 'r0kh=' || true")
            r1kh = ssh.run("uci show wireless | grep 'r1kh=' || true")
            
            if r0kh.strip() and r1kh.strip():
                r0_count = len([l for l in r0kh.strip().split('\n') if 'r0kh=' in l])
                r1_count = len([l for l in r1kh.strip().split('\n') if 'r1kh=' in l])
                print(f"  R0KH/R1KH: {r0_count}/{r1_count} entries")
            
            # Check runtime via ubus
            print(f"  {Fore.CYAN}Runtime status:{Style.RESET_ALL}")
            
            hostapd_ifaces = ssh.run("ubus list | grep 'hostapd\\.phy' || true")
            
            for iface_line in hostapd_ifaces.strip().split('\n'):
                iface = iface_line.strip()
                if not iface:
                    continue
                
                try:
                    nr_output = ssh.run(f"ubus call {iface} rrm_nr_list 2>/dev/null || echo '{{}}'")
                    nr_data = json.loads(nr_output)
                    
                    if 'list' in nr_data:
                        count = len(nr_data.get('list', []))
                        if count > 0:
                            print(f"    {iface}: {Fore.GREEN}{count} neighbors active ✓{Style.RESET_ALL}")
                        else:
                            print(f"    {iface}: {Fore.YELLOW}0 neighbors (waiting for service restart?){Style.RESET_ALL}")
                
                except:
                    print(f"    {iface}: (could not query)")
    
    except Exception as e:
        print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")


# ============================================================================
# Main
# ============================================================================

def main():
    print(f"{Fore.GREEN}{'='*70}")
    print("OpenWrt 802.11r/k/v Auto-Configuration Script")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    # Load configuration
    config = load_config()
    
    ssid = config['ssid']
    mobility_domain = config['mobility_domain']
    ssh_user = config['ssh_user']
    dry_run = config['dry_run']
    ap_hosts = config['ap_hosts']
    
    print(f"Configuration:")
    print(f"  SSID: {ssid}")
    print(f"  Mobility Domain: {mobility_domain}")
    print(f"  APs: {', '.join(ap_hosts)}")
    print(f"  Mode: {Fore.YELLOW}DRY RUN{Style.RESET_ALL}" if dry_run else f"  Mode: {Fore.RED}LIVE (will apply changes){Style.RESET_ALL}")
    print()
    
    if dry_run:
        print(f"{Fore.YELLOW}{'='*70}")
        print("DRY RUN MODE - No changes will be applied")
        print(f"{'='*70}{Style.RESET_ALL}\n")
    
    # Step 1: Collect AP information
    print(f"{Fore.YELLOW}Step 1: Collecting AP information...{Style.RESET_ALL}\n")
    
    all_aps = []
    failed_aps = []
    
    for hostname in ap_hosts:
        try:
            ap_info = collect_ap_info(hostname, ssid)
            if ap_info:
                all_aps.append(ap_info)
            else:
                failed_aps.append(hostname)
            print()
        except Exception as e:
            print(f"\n{Fore.RED}FATAL: Could not connect to {hostname}{Style.RESET_ALL}")
            print(f"Error: {e}\n")
            print(f"{Fore.RED}Aborting - all APs must be reachable!{Style.RESET_ALL}")
            sys.exit(1)
    
    if not all_aps:
        print(f"\n{Fore.RED}No APs found! Check hostnames and SSH connectivity.{Style.RESET_ALL}")
        sys.exit(1)
    
    if failed_aps:
        print(f"\n{Fore.RED}Some APs did not have matching SSID: {', '.join(failed_aps)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Aborting!{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}✓ All {len(all_aps)} APs reachable and configured{Style.RESET_ALL}")
    
    # Step 2: Generate shared secret
    print(f"\n{Fore.YELLOW}Step 2: Generating shared secret for R0KH/R1KH...{Style.RESET_ALL}\n")
    shared_secret = secrets.token_hex(32)
    print(f"  Secret (64 hex chars): {shared_secret[:24]}...{shared_secret[-16:]}")
    
    # Step 3: Configure neighbor reports
    print(f"\n{Fore.YELLOW}Step 3: Configuring 802.11k neighbor reports (cross-band)...{Style.RESET_ALL}")
    
    for ap in all_aps:
        configure_neighbors(ap, all_aps, ssid, dry_run)
    
    # Step 4: Configure R0KH/R1KH
    print(f"\n{Fore.YELLOW}Step 4: Configuring R0KH/R1KH for 802.11r PMK R1 Push...{Style.RESET_ALL}")
    
    for ap in all_aps:
        configure_r0kh_r1kh(ap, all_aps, mobility_domain, shared_secret, dry_run)
    
    # Step 5: Verify
    if not dry_run:
        print(f"\n{Fore.YELLOW}Step 5: Verifying configuration...{Style.RESET_ALL}")
        
        for ap in all_aps:
            verify_configuration(ap)
    
    # Summary
    print(f"\n{Fore.GREEN}{'='*70}")
    if dry_run:
        print("DRY RUN Complete - Review output above")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}To apply changes:{Style.RESET_ALL}")
        print('  1. Edit roaming-config.json and set: "dry_run": false')
        print("  2. Run script again")
    else:
        print("Configuration Complete!")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print("Configured APs:")
        for ap in all_aps:
            print(f"  ✓ {ap.hostname}")
            if ap.interface_24:
                print(f"    2.4G: {ap.interface_24.mac} (ch {ap.interface_24.channel})")
            if ap.interface_5:
                print(f"    5G: {ap.interface_5.mac} (ch {ap.interface_5.channel})")
    
        print(f"\n{Fore.CYAN}Verify with these commands:{Style.RESET_ALL}")
        print(f"  # Check neighbor reports:")
        if all_aps[0].interface_24:
            iface = all_aps[0].interface_24.interface
            print(f"  ssh root@{all_aps[0].hostname} \"ubus call hostapd.{iface} rrm_nr_list\"")
        print(f"\n  # Monitor roaming events:")
        print(f"  ssh root@{all_aps[0].hostname} \"logread -f | grep -E 'PMK|R0KH|R1KH|FT'\"")
        print(f"\n  # Test from client:")
        print(f"  iw dev wlan0 scan | grep -A 30 '{ssid}'")
        print(f"  wpa_cli -i wlan0 neighbor_rep_request")

    print()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

