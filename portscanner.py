import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from queue import Queue

def check_single_port(ip, port):
    """Attempts to connect to a single port and returns True on success."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except (socket.error, socket.timeout):
        return False

def check_host_status(ip, result_queue):
    """Checks if a host is online by attempting to connect to multiple common ports."""
    common_ports = [80, 443, 22]
    for port in common_ports:
        if check_single_port(ip, port):
            result_queue.put(True)
            return
    result_queue.put(False)

def scan_ports(ip, ports, output_text):
    """Scans a list of ports and updates the GUI with the results."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, port))
            output_text.insert(tk.END, f"Port {port} is open ✅\n")
            s.close()
        except (socket.error, socket.timeout):
            output_text.insert(tk.END, f"Port {port} is closed ❌\n")
            pass
        output_text.see(tk.END)

def start_scan():
    """Main function to be called by the GUI button."""
    ip = ip_entry.get()
    output_text.delete(1.0, tk.END)

    if not ip:
        output_text.insert(tk.END, "Please enter an IP address.\n")
        return

    output_text.insert(tk.END, f"Checking if host {ip} is online...\n")

    # Use a Queue to pass the result from the thread back to the main program
    result_queue = Queue()
    host_check_thread = threading.Thread(target=check_host_status, args=(ip, result_queue))
    host_check_thread.start()
    host_check_thread.join() # Wait for the thread to complete

    is_online = result_queue.get() # Get the result from the Queue

    if is_online:
        output_text.insert(tk.END, f"Host {ip} is online! 👍\n\n")
        ports_to_scan = [21, 22, 23, 25, 80, 139, 443, 445]
        output_text.insert(tk.END, "Starting port scan...\n")
        
        # Use a thread for the port scan to prevent GUI freeze
        scan_thread = threading.Thread(target=scan_ports, args=(ip, ports_to_scan, output_text))
        scan_thread.start()
    else:
        output_text.insert(tk.END, f"Host {ip} appears to be offline. 😞\n")

# --- GUI Setup ---
root = tk.Tk()
root.title("Network Scanner")
root.geometry("400x400")

# Input Frame
input_frame = tk.Frame(root)
input_frame.pack(pady=10)

ip_label = tk.Label(input_frame, text="Enter IPv4 Address:")
ip_label.pack(side=tk.LEFT, padx=5)

ip_entry = tk.Entry(input_frame, width=20)
ip_entry.pack(side=tk.LEFT)

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=5)

# Output Textbox
output_text = scrolledtext.ScrolledText(root, width=45, height=15)
output_text.pack(pady=10)

root.mainloop()
