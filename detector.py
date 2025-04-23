import psutil
import time
import threading
from datetime import datetime
from scapy.all import sniff, TCP, Raw
from scapy.layers.inet import IP
import tkinter as tk
from tkinter import scrolledtext
from collections import defaultdict, deque

smtp_ports = [465, 25, 587, 2525]
ftp_ports = [20, 21]
http_ports = [80, 443]
detected = set()

class PacketSnifferDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet sniffing for Detection of Suspicious Key-Logger Activity")
        self.root.geometry("1280x720")

        self.packet_log = []  # Store packet logs
        self.process_log = []  # Store process logs

        bottom_frame = tk.Frame(root)
        bottom_frame.pack(fill='x', padx=10)

        # Left side for status label
        left_frame = tk.Frame(bottom_frame)
        left_frame.pack(side=tk.LEFT, fill='x', expand=True)

        self.status_label = tk.Label(left_frame, text="Status: Idle", anchor='w', font=("TkDefaultFont", 12))
        self.status_label.pack(side=tk.LEFT, pady=(15, 0), ipadx=5)

        # Right side for buttons
        right_frame = tk.Frame(bottom_frame)
        right_frame.pack(side=tk.RIGHT)

        self.start_button = tk.Button(right_frame, text="Start", command=self.start_monitoring)
        self.start_button.pack(side=tk.RIGHT, padx=5, pady=(15, 0), ipadx=5)
        
        self.stop_button = tk.Button(right_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=5, pady=(15, 0), ipadx=5)

        # === MAIN LOG AREA
        main_frame = tk.Frame(root)
        main_frame.pack(expand=True, fill='both')
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        # Left: Process Logs
        process_frame = tk.LabelFrame(main_frame, text="Process Logs")
        process_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        self.process_text = scrolledtext.ScrolledText(process_frame, wrap=tk.WORD, font=("Consolas", 10), state='disabled')
        self.process_text.pack(fill='both', expand=True)
        # Right: Packet Logs
        packet_frame = tk.LabelFrame(main_frame, text="Packet Logs")
        packet_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        self.packet_text = scrolledtext.ScrolledText(packet_frame, wrap=tk.WORD, font=("Consolas", 10), state='disabled')
        self.packet_text.pack(fill='both', expand=True)

        # === SUSPICIOUS WARNINGS ===
        warning_frame = tk.LabelFrame(root, text="Suspicious Warnings")
        warning_frame.pack(fill='x', padx=5, pady=(0, 5))

        self.warning_text = scrolledtext.ScrolledText(warning_frame, height=12, font=("Consolas", 10), state='disabled')
        self.warning_text.pack(fill='x')

        self.running = False

        self.packet_count = 0
        self.suspicious_count = 0
        self.process_count = 0

        # Create a frame to hold stats label and clear button
        stats_frame = tk.Frame(root)
        stats_frame.pack(fill='x', padx=10, pady=(0, 10))

        self.stats_label = tk.Label(stats_frame, text="Packets: 0 | Process: 0 | Suspicious: 0", anchor='w')
        self.stats_label.pack(side=tk.LEFT)

        self.clear_button = tk.Button(stats_frame, text="Clear", command=self.clear_logs)
        self.clear_button.pack(side=tk.RIGHT, padx=10, ipadx=5)

        self.repetition_tracker = defaultdict(lambda: deque(maxlen=100))  
        self.repeat_threshold = 3  # Minimum number of similar intervals to mark as repeated
        self.interval_margin = 3   # Acceptable margin for repeated interval (in seconds)

    def process_logging(self, message):
        self.process_text.config(state='normal')
        self.process_text.insert(tk.END, message + "\n")
        self.process_text.yview(tk.END)
        self.process_text.config(state='disabled')

    def packet_logging(self, message):
        self.packet_text.config(state='normal')
        self.packet_text.insert(tk.END, message + "\n")
        self.packet_text.yview(tk.END)
        self.packet_text.config(state='disabled')

    def warning_logging(self, message):
        self.warning_text.config(state='normal')
        self.warning_text.insert(tk.END, message + "\n")
        self.warning_text.yview(tk.END)
        self.warning_text.config(state='disabled')

    def clear_logs(self):
        self.packet_log.clear()
        self.process_log.clear()

        self.process_text.config(state=tk.NORMAL)
        self.process_text.delete('1.0', tk.END)
        self.process_text.insert(tk.END, "📡 Logs cleared. Ready to monitor network activity...\n\n")
        self.process_text.config(state=tk.DISABLED)

        self.packet_text.config(state=tk.NORMAL)
        self.packet_text.delete('1.0', tk.END)
        self.packet_text.insert(tk.END, "📡 Logs cleared. Ready to monitor network activity...\n\n")
        self.packet_text.config(state=tk.DISABLED)

        self.packet_count = 0
        self.process_count = 0
        self.suspicious_count = 0
        self.stats_label.config(text="Packets: 0 | Process: 0 | Suspicious: 0")

    def detect_smtp_activity(self):
        global detected
        while self.running:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    self.process_count += 1
                    ip, port = conn.raddr
                    if port in smtp_ports:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = ' '.join(proc.cmdline())
                            key = (conn.pid, ip, port)
                            if key not in detected:
                                detected.add(key)
                                self.suspicious_count += 1
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                entry = (
                                    f"[{timestamp}] ⚠️ SMTP connection detected:\n"
                                    f"   PID: {conn.pid}, Process: {proc.name()}, IP: {ip}:{port}\n"
                                    f"   CMD: {cmdline}\n\n"
                                    f"{'-'*60}\n"
                                )
                                self.warning_logging(entry)
                                self.process_log.append((True, entry))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    else:
                        entry = (
                            f"[{datetime.now().strftime('%H:%M:%S')}] Normal Process: {conn.laddr} → {conn.raddr}"
                        )
                        self.process_log.append((False, entry))
                        self.process_logging(entry)
            time.sleep(10)
    
    def detect_ftp_activity(self):
        global detected
        while self.running:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    self.process_count += 1
                    ip, port = conn.raddr
                    if port in ftp_ports:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = ' '.join(proc.cmdline())
                            key = (conn.pid, ip, port)
                            if key not in detected:
                                detected.add(key)
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                entry = (
                                    f"[{timestamp}] ⚠️ FTP connection detected:\n"
                                    f"   PID: {conn.pid}, Process: {proc.name()}, IP: {ip}:{port}\n"
                                    f"   CMD: {cmdline}\n\n"
                                    f"{'-'*60}\n"
                                )
                                print(entry)
                                self.warning_logging(entry)
                                self.process_log.append((True, entry))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    else:
                        entry = (
                            f"[{datetime.now().strftime('%H:%M:%S')}] Normal Process: {conn.laddr} → {conn.raddr}"
                        )
                        self.process_logging(entry)
                        self.process_log.append((False, entry))
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

            dst_ip = packet[IP].dst if IP in packet else "unknown"

            # Repetition Behavior Detection
            if dst_ip:
                key = f"{dst_ip}:{len(payload_str)}"
                current_time = datetime.strptime(timestamp, "%H:%M:%S")
                
                # Store the timestamp as datetime object for accurate interval calculation
                self.repetition_tracker[key].append(current_time)
                
                # We need at least 3 timestamps to detect a pattern
                if len(self.repetition_tracker[key]) >= 3:
                    # Calculate time intervals between consecutive timestamps
                    intervals = []
                    for i in range(1, len(self.repetition_tracker[key])):
                        prev_time = self.repetition_tracker[key][i-1]
                        curr_time = self.repetition_tracker[key][i]
                        
                        # Calculate difference in seconds
                        diff = (curr_time - prev_time).total_seconds()
                        if diff < 0:  # Handle midnight crossing
                            diff += 24 * 60 * 60
                        intervals.append(diff)
                    
                    # Group similar intervals to detect patterns
                    interval_groups = defaultdict(int)
                    for interval in intervals:
                        # Round to nearest second for grouping
                        rounded_interval = round(interval)
                        interval_groups[rounded_interval] += 1
                        
                    # Find the most common interval
                    most_common_interval = None
                    max_count = 0
                    for interval, count in interval_groups.items():
                        if count > max_count:
                            max_count = count
                            most_common_interval = interval
                            
                    # Determine if we have a suspicious pattern
                    # At least 3 occurrences of the same interval and interval is between 1-60 seconds
                    if most_common_interval and max_count >= self.repeat_threshold and 50 <= most_common_interval <= 70:
                        is_suspicious = True
                        self.suspicious_count += 1
                        entry = (
                            f"[{timestamp}] 🚨 REPETITIVE BEHAVIOR DETECTED!\n"
                            f"Pattern: {dst_ip} receiving data every ~{most_common_interval} seconds\n"
                            f"Protocol:    {proto_label}\n"
                            f"Source:      {src_ip}:{src_port}\n"
                            f"Destination: {dst_ip}:{dst_port}\n"
                            f"Occurrences: {max_count} times\n"
                            f"Payload size: {len(payload_str)} bytes\n\n"
                            f"{'-'*60}\n"
                        )
                        self.warning_logging(entry)
                        self.packet_log.append((True, entry))

            self.packet_count += 1
            if is_suspicious == False:
                entry = f"{proto_label} [{timestamp}] Normal TCP: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
                self.packet_log.append((False, entry))
                self.packet_logging(entry)
            
            self.stats_label.config(text=f"📊 Packets: {self.packet_count} | Process: {self.process_count} | Suspicious: {self.suspicious_count}")

    def start_sniffing(self):
        sniff(filter="tcp", prn=self.handle_packet, store=False, stop_filter=lambda x: not self.running)

    def start_monitoring(self):
        if not self.running:
            self.status_label.config(text="Status: Monitoring...")
            self.running = True

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
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferDetector(root)
    root.mainloop()
