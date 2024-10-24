import scapy.all as scapy
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import threading
import time
from collections import Counter
import tkinter as tk
from tkinter import ttk

traffic_data = {
    'src_ips': [],
    'dst_ips': [],
    'protocols': []
}

connected_devices = set()
external_devices = set()


def capture_packets_live(router_ip, packet_count=0):
    try:
        # Capture packets related to the router IP (incoming/outgoing traffic)
        capture_filter = f"host {router_ip}"
        scapy.sniff(filter=capture_filter, prn=process_packet, store=False, count=packet_count)
    except Exception as e:
        print(f"Error capturing packets on {router_ip}: {e}")


def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Add IP addresses to connected devices set
        connected_devices.add(src_ip)
        connected_devices.add(dst_ip)

        # Identify external IPs (not in the local subnet)
        local_ip_prefix = "192.168.0."
        if not src_ip.startswith(local_ip_prefix):
            external_devices.add(src_ip)
        if not dst_ip.startswith(local_ip_prefix):
            external_devices.add(dst_ip)

        # Update traffic data
        traffic_data['src_ips'].append(src_ip)
        traffic_data['dst_ips'].append(dst_ip)
        traffic_data['protocols'].append(protocol)


def update_gui():
    internal_devices_list.delete(0, tk.END)
    external_devices_list.delete(0, tk.END)

    for device in connected_devices:
        internal_devices_list.insert(tk.END, device)

    for device in external_devices:
        external_devices_list.insert(tk.END, device)

    # Schedule the function to run again after 1 second
    root.after(1000, update_gui)


def live_plot_connected_devices():
    fig, ax = plt.subplots(figsize=(10, 6))  # Set a fixed figure size
    plt.xlabel("Connected Devices (IPs)")
    plt.ylabel("Number of Packets Sent To Samson Router")
    fig.text(0.5, 0.01, "Live Tracking of Connected Devices", ha='center', va='center')
    fig.subplots_adjust(left=0.2, right=0.8, top=0.8, bottom=0.2)

    def update(frame):
        ax.clear()
        ip_count = Counter(traffic_data['src_ips'])
        ips = list(ip_count.keys())
        counts = list(ip_count.values())
        ax.bar(ips, counts)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.xlabel("Connected Devices (IPs)")
        plt.ylabel("Number of Packets Sent")
        plt.title("Live Tracking of Connected Devices")

    ani = animation.FuncAnimation(fig, update, interval=1000)
    plt.show()


if __name__ == "__main__":
    router_ip = '192.168.0.73'  

    # Start GUI
    root = tk.Tk()
    root.title("Network Traffic Analyzer")
    root.geometry("600x400")

    # Create frames for internal and external devices
    frame_internal = ttk.LabelFrame(root, text="Internal Devices")
    frame_internal.pack(fill="both", expand=True, padx=10, pady=5)

    frame_external = ttk.LabelFrame(root, text="External Devices")
    frame_external.pack(fill="both", expand=True, padx=10, pady=5)

    # Create listboxes to display connected devices
    internal_devices_list = tk.Listbox(frame_internal)
    internal_devices_list.pack(fill="both", expand=True, padx=10, pady=5)

    external_devices_list = tk.Listbox(frame_external)
    external_devices_list.pack(fill="both", expand=True, padx=10, pady=5)

    # Start capturing packets related to the router
    try:
        capture_thread = threading.Thread(target=capture_packets_live, args=(router_ip,))
        capture_thread.daemon = True
        capture_thread.start()
    except Exception as e:
        print(f"Error starting packet capture thread: {e}")

    # Live tracking of connected devices in a separate thread
    plot_thread = threading.Thread(target=live_plot_connected_devices)
    plot_thread.daemon = True
    plot_thread.start()

    # Update GUI with connected devices
    update_gui()

    root.mainloop()
