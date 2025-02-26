import scapy.all as scapy
import os
import logging
import tkinter as tk
from tkinter import messagebox
from collections import defaultdict
import threading

# Configure logging for blocked traffic
logging.basicConfig(filename="firewall_log.txt", level=logging.INFO, format="%(asctime)s - BLOCKED: %(message)s")

# Define firewall rule table
FIREWALL_RULES = {
    ("192.168.1.10", "192.168.1.20"): "ALLOW",
    ("192.168.1.20", "192.168.1.30"): "BLOCK",
    ("192.168.1.30", "192.168.1.40"): "ALLOW",
    ("192.168.1.40", "192.168.1.10"): "BLOCK",
}

# Track packet counts per IP for attack detection
PACKET_COUNT = defaultdict(int)
THRESHOLD = 20  # Threshold for detecting DoS or malicious behavior
BLOCKED_IPS = set()

# Function to apply firewall rules dynamically
def apply_iptables_rules():
    os.system("sudo iptables -F")  # Clear old rules
    for (src, dst), action in FIREWALL_RULES.items():
        cmd = f"sudo iptables -A FORWARD -s {src} -d {dst} -j {'DROP' if action == 'BLOCK' else 'ACCEPT'}"
        os.system(cmd)
        print(f"Applied Rule: {action} traffic from {src} to {dst}")

# Function to block an IP dynamically
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        BLOCKED_IPS.add(ip)
        logging.info(f"Blocked IP: {ip} for suspected attack")
        show_alert(f"Blocked Malicious IP: {ip}")

# Function to show an alert popup for blocked traffic
def show_alert(message):
    root = tk.Tk()
    root.withdraw()  # Hide main window
    messagebox.showwarning("Firewall Alert", message)

# Packet sniffer callback function for monitoring traffic
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Detect abnormal packet rates (potential DoS)
        PACKET_COUNT[src_ip] += 1
        if PACKET_COUNT[src_ip] > THRESHOLD:
            print(f"Potential Attack Detected! Blocking {src_ip}")
            block_ip(src_ip)

        # Apply predefined firewall rules
        if (src_ip, dst_ip) in FIREWALL_RULES:
            action = FIREWALL_RULES[(src_ip, dst_ip)]
            print(f"Traffic from {src_ip} to {dst_ip}: {action}")

            if action == "BLOCK":
                logging.info(f"Blocked traffic from {src_ip} to {dst_ip}")
                show_alert(f"Blocked traffic from {src_ip} to {dst_ip}")
                return  # Drop packet

        # Allow normal packets to pass
        scapy.send(packet)

# GUI Interface for Managing Rules
def firewall_gui():
    def add_rule():
        src = src_entry.get()
        dst = dst_entry.get()
        action = action_var.get()
        if src and dst and action:
            FIREWALL_RULES[(src, dst)] = action
            apply_iptables_rules()
            rule_list.insert(tk.END, f"{src} -> {dst}: {action}")
            src_entry.delete(0, tk.END)
            dst_entry.delete(0, tk.END)

    def remove_rule():
        selected = rule_list.curselection()
        if selected:
            rule_text = rule_list.get(selected[0])
            src, dst_action = rule_text.split(" -> ")
            dst, action = dst_action.split(": ")
            FIREWALL_RULES.pop((src.strip(), dst.strip()), None)
            apply_iptables_rules()
            rule_list.delete(selected)

    gui = tk.Tk()
    gui.title("Firewall Rule Manager")

    tk.Label(gui, text="Source IP:").grid(row=0, column=0)
    src_entry = tk.Entry(gui)
    src_entry.grid(row=0, column=1)

    tk.Label(gui, text="Destination IP:").grid(row=1, column=0)
    dst_entry = tk.Entry(gui)
    dst_entry.grid(row=1, column=1)

    tk.Label(gui, text="Action:").grid(row=2, column=0)
    action_var = tk.StringVar(value="ALLOW")
    action_menu = tk.OptionMenu(gui, action_var, "ALLOW", "BLOCK")
    action_menu.grid(row=2, column=1)

    add_button = tk.Button(gui, text="Add Rule", command=add_rule)
    add_button.grid(row=3, column=0)

    remove_button = tk.Button(gui, text="Remove Selected Rule", command=remove_rule)
    remove_button.grid(row=3, column=1)

    rule_list = tk.Listbox(gui, width=40, height=10)
    rule_list.grid(row=4, column=0, columnspan=2)

    for (src, dst), action in FIREWALL_RULES.items():
        rule_list.insert(tk.END, f"{src} -> {dst}: {action}")

    gui.mainloop()

# Apply firewall rules at startup
apply_iptables_rules()

# Start GUI in a separate thread
gui_thread = threading.Thread(target=firewall_gui)
gui_thread.start()

# Start packet sniffing
print("Starting firewall...")
sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=packet_callback, store=False))
sniff_thread.start()

