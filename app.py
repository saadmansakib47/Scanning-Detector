from flask import Flask, render_template, send_file
from flask_socketio import SocketIO
import threading
from datetime import datetime
from flask_cors import CORS
import pyshark
import asyncio

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "detection_log.txt"

open(LOG_FILE, "a").close()

# scanning detection and logging function
def detect_scan(packet):
    try:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            src_ip = packet.ip.src
            dst_port = int(tcp_layer.dstport)
            tcp_flags = int(tcp_layer.flags, 16)

            if dst_port in [80, 443, 5000]:
                return

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Scan Type Detection
            log_message = None
            if tcp_flags & 0x02:  # SYN bit set
                log_message = f"{timestamp} - SYN scan detected from {src_ip}"
            elif tcp_flags & 0x01:  # FIN bit set
                log_message = f"{timestamp} - FIN scan detected from {src_ip}"
            elif tcp_flags == 0x00:  # NULL scan (no flags set)
                log_message = f"{timestamp} - NULL scan detected from {src_ip}"
            elif tcp_flags & 0x29 == 0x29:  # XMAS scan (URG+PSH+FIN)
                log_message = f"{timestamp} - XMAS scan detected from {src_ip}"
            elif tcp_flags & 0x10:  # ACK scan
                log_message = f"{timestamp} - ACK scan detected from {src_ip}"

            if log_message:
                with open(LOG_FILE, "a") as log:
                    log.write(log_message + "\n")
                socketio.emit('scan_alert', {'message': log_message})
    except AttributeError:
        pass

def start_sniffer():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=r'\Device\NPF_Loopback')  # Loopback interface for Windows
    for packet in capture.sniff_continuously():
        detect_scan(packet)

# Route for the main page
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/download-log")
def download_log():
    return send_file(LOG_FILE, as_attachment=True)

if __name__ == "__main__":
    threading.Thread(target=start_sniffer, daemon=True).start()
    socketio.run(app, debug=True)
