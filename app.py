from flask import Flask, render_template, send_file
from flask_socketio import SocketIO
from scapy.all import sniff
from scapy.layers.inet import TCP
import threading
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app)  # Initialize SocketIO

LOG_FILE = "detection_log.txt"

# Ensure the log file exists
open(LOG_FILE, "a").close()

# Function to detect scans and log them
def detect_scan(packet):
    if packet.haslayer(TCP):  # Check for TCP layer
        tcp_flags = packet['TCP'].flags  # Extract TCP flags
        src_ip = packet[0][1].src  # Source IP of the packet

        # Get the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(LOG_FILE, "a") as log:
            if tcp_flags == 0x02:  # SYN
                log.write(f"{timestamp} - SYN scan detected from {src_ip}\n")
                socketio.emit('scan_alert', {'message': f"SYN scan detected from {src_ip}"})  # Emit alert
            elif tcp_flags == 0x29:  # XMAS
                log.write(f"{timestamp} - XMAS scan detected from {src_ip}\n")
                socketio.emit('scan_alert', {'message': f"XMAS scan detected from {src_ip}"})  # Emit alert
            elif tcp_flags == 0x01:  # FIN
                log.write(f"{timestamp} - FIN scan detected from {src_ip}\n")
                socketio.emit('scan_alert', {'message': f"FIN scan detected from {src_ip}"})  # Emit alert
            elif tcp_flags == 0x00:  # NULL
                log.write(f"{timestamp} - NULL scan detected from {src_ip}\n")
                socketio.emit('scan_alert', {'message': f"NULL scan detected from {src_ip}"})  # Emit alert

# Start packet sniffing in a separate thread
def start_sniffer():
    sniff(filter="tcp", prn=detect_scan, store=0)

# Route for the main page
@app.route("/")
def home():
    return render_template("index.html")

# Route to download the log file
@app.route("/download-log")
def download_log():
    return send_file(LOG_FILE, as_attachment=True)

if __name__ == "__main__":
    # Run the sniffer in a background thread
    threading.Thread(target=start_sniffer, daemon=True).start()
    # Start the Flask-SocketIO server
    socketio.run(app, debug=True)
