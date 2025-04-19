import psutil
import time
import threading
from datetime import datetime
from scapy.all import sniff, TCP, Raw
from scapy.layers.inet import IP
import tkinter as tk
from tkinter import scrolledtext

smtp_ports = [465, 25, 587, 2525]
ftp_ports = [20, 21]
http_ports = [80, 443]
detected = set()

class PacketSnifferDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("SMTP, FTP Detector + Packet Sniffer")
        self.root.geometry("800x500")

        self.status_label = tk.Label(root, text="Status: Idle", anchor='w', font=("TkDefaultFont", 12))
        self.status_label.pack(fill='x', padx=10, pady=10)

        self.packet_log = []  # Store packet logs

        # inside your GUI class __init__ method
        self.show_all_var = tk.BooleanVar()
        self.show_all_var.set(False)
        show_all_checkbox = tk.Checkbutton(root, text="Show All Packets", variable=self.show_all_var, command=self.refresh_log)
        show_all_checkbox.pack(anchor='w', padx=10)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
        self.text_area.pack(expand=True, fill='both', padx=10, pady=5)
        self.text_area.insert(tk.END, "📡 Ready to monitor network activity...\n\n")
        self.text_area.config(state='disabled')

        self.running = False

        self.stats_label = tk.Label(root, text="Packets: 0 | Suspicious: 0", anchor='w')
        self.stats_label.pack(fill='x', padx=10, pady=5)
        self.packet_count = 0
        self.suspicious_count = 0

        self.start_button = tk.Button(root, text="Start", command=self.start_monitoring)
        self.start_button.pack(side=tk.RIGHT, padx=16, pady=5)

        self.stop_button = tk.Button(root, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=16)


    def log(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')

    def refresh_log(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete('1.0', tk.END)
        for is_suspicious, entry in self.packet_log:
            if is_suspicious or self.show_all_var.get():
                self.text_area.insert(tk.END, entry + "\n")
        self.text_area.config(state=tk.DISABLED)

    def detect_smtp_activity(self):
        global detected
        while self.running:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    ip, port = conn.raddr
                    if port in smtp_ports:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = ' '.join(proc.cmdline())
                            key = (conn.pid, ip, port)
                            if key not in detected:
                                detected.add(key)
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.log(f"[{timestamp}] ⚠️ SMTP connection detected:")
                                self.log(f"   PID: {conn.pid}, Process: {proc.name()}, IP: {ip}:{port}")
                                self.log(f"   CMD: {cmdline}\n")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            time.sleep(10)
    
    def detect_ftp_activity(self):
        global detected
        while self.running:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    ip, port = conn.raddr
                    if port in ftp_ports:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = ' '.join(proc.cmdline())
                            key = (conn.pid, ip, port)
                            if key not in detected:
                                detected.add(key)
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.log(f"[{timestamp}] ⚠️ FTP connection detected:")
                                self.log(f"   PID: {conn.pid}, Process: {proc.name()}, IP: {ip}:{port}")
                                self.log(f"   CMD: {cmdline}\n")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            time.sleep(10)

    # Low-Level Packet Sniffing (Scapy)
    def handle_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            timestamp = datetime.now().strftime("%H:%M:%S")

            proto_label = ""
            if dst_port in smtp_ports:
                proto_label = "[SMTP]"
            elif dst_port in ftp_ports:
                proto_label = "[FTP]"
            elif dst_port in http_ports:
                proto_label = "[HTTP/HTTPS]"

            is_suspicious = False
            reason = ""
            payload_str = ""

            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    payload_str = raw_data.decode(errors='replace')
                except:
                    payload_str = repr(raw_data)

                if any(keyword in payload_str.lower() for keyword in ["password", "username", "login", "key="]):
                    is_suspicious = True
                    reason = "🔐 Suspicious keyword"
                elif 1 < len(payload_str) < 20:
                    is_suspicious = True
                    reason = "⌨️ Small payload (possible keystroke)"

            self.packet_count += 1
            if is_suspicious:
                self.suspicious_count += 1
                entry = (
                    f"[{timestamp}] 🔍 Suspicious Packet Detected ({reason})\n"
                    f"Protocol:    {proto_label}\n"
                    f"Source:      {src_ip}:{src_port}\n"
                    f"Destination: {dst_ip}:{dst_port}\n"
                    f"Payload Size: {len(payload_str)} bytes\n\n"
                    f"{'-'*60}\n"
                )
                self.packet_log.append((True, entry))
                self.log(entry)
            else:
                entry = f"{proto_label} [{timestamp}] Normal TCP: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
                self.packet_log.append((False, entry))
                if self.show_all_var.get():
                    self.log(entry)
            self.stats_label.config(text=f"📊 Packets: {self.packet_count} | Suspicious: {self.suspicious_count}")

    def start_sniffing(self):
        sniff(filter="tcp", prn=self.handle_packet, store=False, stop_filter=lambda x: not self.running)

    def start_monitoring(self):
        if not self.running:
            self.status_label.config(text="Status: Monitoring...")
            self.running = True
            self.log("✅ Monitoring started...\n")

            self.smtp_thread = threading.Thread(target=self.detect_smtp_activity, daemon=True)
            self.ftp_thread = threading.Thread(target=self.detect_ftp_activity, daemon=True)
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)

            self.smtp_thread.start()
            self.sniff_thread.start()
            self.ftp_thread.start()

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def stop_monitoring(self):
        self.running = False
        self.status_label.config(text="Status: Idle")
        self.log("\n👋 Monitoring stopped.")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferDetector(root)
    root.mainloop()
