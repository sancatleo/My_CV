from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP, DNS, DNSQR, rdpcap
import threading
import psutil
import nmap
import pyshark
import datetime
import subprocess
import io
import requests
import random
import time
import os
from fpdf import FPDF

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flash messages

# Global variables
interface = None
packet_count_per_ip = {}
detected_threats = {}
analysis_running = False
packet_list = []
PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", 
    "password", "billing", "confirm", "identity", "urgent"
]

# For live data tracking
live_data = []
live_data_lock = threading.Lock()

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    if isinstance(interfaces, dict):
        return list(interfaces.keys())
    elif isinstance(interfaces, list):
        return interfaces
    else:
        return []

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/network_detect', methods=['GET', 'POST'])
def network_detect():
    global interface, analysis_running

    if request.method == 'POST':
        if 'start_analysis' in request.form:
            interface = request.form.get('interface')
            analysis_running = True
            threading.Thread(target=analyze_real_time, daemon=True).start()
        elif 'stop_analysis' in request.form:
            analysis_running = False
        elif 'save_pdf' in request.form:
            return save_as_pdf()
    
    return render_template('network_detect.html', interfaces=get_network_interfaces(), 
                           packet_count=packet_count_per_ip, threats=detected_threats)

@app.route('/port_detect', methods=['GET', 'POST'])
def port_detect():
    scan_result = None
    error_message = None
    
    if request.method == 'POST':
        if 'start_scan' in request.form:
            target = request.form.get('target')
            if target:
                try:
                    scan_result = scan_ports(target)
                    flash("Port scan completed successfully.", "success")
                except Exception as e:
                    error_message = f"Port scan failed: {str(e)}"
                    flash(error_message, "error")
            else:
                flash("Target IP or hostname is required.", "warning")

    return render_template('port_detect.html', scan_result=scan_result, error_message=error_message)

def scan_ports(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-T4 -F')
        
        scan_result = ""
        for proto in nm.all_protocols():
            scan_result += f"Protocol: {proto.upper()}\n"
            lports = nm[target][proto].keys()
            for port in sorted(lports):
                state = nm[target][proto][port]['state']
                scan_result += f"Port: {port}, State: {state}\n"
            scan_result += "\n"  # Add a newline for better separation
        
        if not scan_result:
            scan_result = "No open ports found or scan result is empty."
        
        return scan_result

    except Exception as e:
        raise RuntimeError(f"Port scan failed: {str(e)}")

def analyze_packet(packet):
    global packet_count_per_ip, detected_threats

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.payload.name

        key = (src_ip, dst_ip, protocol)
        if key not in packet_count_per_ip:
            packet_count_per_ip[key] = 0

        packet_count_per_ip[key] += 1

        threat_detected, threat_message, mitigation_strategies, suspicious_ips = detect_security_threats(packet)

        if threat_detected:
            for suspicious_ip in suspicious_ips:
                if suspicious_ip not in detected_threats:
                    detected_threats[suspicious_ip] = []

                threat_info = (threat_message, mitigation_strategies)
                if threat_info not in detected_threats[suspicious_ip]:
                    detected_threats[suspicious_ip].append(threat_info)

def detect_security_threats(packet):
    threat_detected = False
    threat_message = "No security threats detected."
    mitigation_strategies = []
    suspicious_ips = set()

    if UDP in packet:
        source_ip = packet[IP].src
        udp_length = len(packet[UDP])
        if udp_length > 100:
            threat_detected = True
            threat_message = "UDP flood detected!"
            mitigation_strategies.append("Implement UDP rate limiting.")
            suspicious_ips.add(source_ip)

    if ICMP in packet and packet[ICMP].type == 8:
        source_ip = packet[IP].src
        icmp_echo_count = packet_count_per_ip.get((source_ip, ICMP), 0)
        if icmp_echo_count > 500:
            threat_detected = True
            threat_message = "ICMP Echo Request flood detected!"
            mitigation_strategies.append("Implement ICMP rate limiting.")
            suspicious_ips.add(source_ip)

    if TCP in packet and packet[TCP].flags.S and not packet[TCP].flags.A:
        threat_detected = True
        threat_message = "SYN flood detected!"
        mitigation_strategies.append("Implement SYN cookies.")
        suspicious_ips.add(packet[IP].src)

    if TCP in packet and packet[TCP].dport == 80 and Raw in packet:
        source_ip = packet[IP].src
        http_payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if len(http_payload) > 2000:
            threat_detected = True
            threat_message = "Potential HTTP flood detected!"
            mitigation_strategies.append("Implement WAF and rate limiting.")
            suspicious_ips.add(source_ip)

    if DNSQR in packet:
        query = packet[DNSQR].qname.decode('utf-8').lower()
        if "http://facebook.com" in query:
            source_ip = packet[IP].src
            threat_detected = True
            threat_message = "Potential DNS amplification attack detected!"
            mitigation_strategies.append("Implement DNS response rate limiting.")
            suspicious_ips.add(source_ip)

    ip_count = {}
    if IP in packet:
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        ip_count[source_ip] = ip_count.get(source_ip, 0) + 1
        ip_count[destination_ip] = ip_count.get(destination_ip, 0) + 1

    for ip, count in ip_count.items():
        if count > 10000:
            suspicious_ips.add(ip)
            threat_detected = True
            threat_message = "High packet rate from a single IP detected!"
            mitigation_strategies = ["Rate-limit incoming packets."]
            if ip not in detected_threats:
                detected_threats[ip] = [(threat_message, mitigation_strategies)]
            else:
                threat_info = (threat_message, mitigation_strategies)
                if threat_info not in detected_threats[ip]:
                    detected_threats[ip].append(threat_info)

    return threat_detected, threat_message, mitigation_strategies, suspicious_ips

def analyze_real_time():
    global interface, analysis_running
    sniff(iface=interface, prn=analyze_packet, stop_filter=lambda x: not analysis_running)

def save_as_pdf():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pdf_buffer = io.BytesIO()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    header = "Network Forensics - Network Analysis Report"
    content = '\n'.join([f"IP: {ip}\nThreats: {', '.join([f'{threat[0]} (Mitigations: {', '.join(threat[1])})' for threat in threats])}" for ip, threats in detected_threats.items()])

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, header, 0, 1, "C")
    pdf.ln(20)
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, content)
    
    # Write the PDF to the BytesIO buffer
    pdf_buffer.write(pdf.output(dest='S').encode('latin1'))
    pdf_buffer.seek(0)

    # Send the PDF as an attachment
    return send_file(pdf_buffer, as_attachment=True, download_name=f"threat_report_{timestamp}.pdf", mimetype='application/pdf')

def capture_packets(interface, duration, filename):
    """
    Captures packets from a specified interface and saves them as a PCAP file.

    Args:
        interface (str): The network interface to capture packets from (e.g., 'eth0', 'wlan0').
        duration (int): Duration of the capture in seconds.
        filename (str): Name of the output file to save the captured packets (e.g., 'capture.pcap').

    Returns:
        str: A message indicating the success or failure of the operation.
    """
    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    
    if not filename.endswith(".pcap"):
        filename += ".pcap"
    
    filepath = os.path.join(downloads_folder, filename)

    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=filepath)
        capture.sniff(timeout=duration)
        return f"Packet capture successful! Saved as {filepath}"
    except Exception as e:
        return f"Packet capture failed: {str(e)}"

@app.route('/capture_packets', methods=['GET', 'POST'])
def capture_packets_route():
    if request.method == 'POST':
        iface = request.form.get('interface')
        duration = int(request.form.get('duration', 10))
        output_file = request.form.get('output_file', 'capture.pcap')

        result = capture_packets(iface, duration, output_file)
        flash(result)
        return redirect(url_for('capture_packets_route'))
    
    return render_template('capture_packets.html', interfaces=get_network_interfaces())

@app.route('/service_discovery', methods=['GET', 'POST'])
def service_discovery():
    scan_result = None
    if request.method == 'POST':
        target = request.form['target']
        if target:
            # Execute Nmap command to discover services
            nmap_command = f"nmap -sV {target}"
            try:
                # Run the Nmap command and capture output
                output = subprocess.check_output(nmap_command, shell=True).decode('utf-8')
                scan_result = output
            except subprocess.CalledProcessError as e:
                scan_result = f"Error: {str(e)}"
    return render_template('service_discovery.html', scan_result=scan_result)

@app.route('/phishing_detector', methods=['GET', 'POST'])
def phishing_detector():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = detect_phishing(url)
    return render_template('phishing_detector.html', result=result)

def detect_phishing(url):
    """Check if a URL is potentially phishing."""
    try:
        response = requests.get(url)
        content = response.text.lower()
        # Check for phishing keywords
        for keyword in PHISHING_KEYWORDS:
            if keyword in content:
                return f"Potential phishing detected: contains '{keyword}'."
        return "URL appears to be safe."
    except requests.exceptions.RequestException as e:
        return f"Error detecting phishing: {str(e)}"


@app.route('/upload-pcap', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            return 'No file part', 400
        file = request.files['pcap_file']
        if file.filename == '':
            return 'No selected file', 400
        if allowed_file(file.filename):
            filepath = os.path.join('/tmp', file.filename)
            file.save(filepath)
            packets = read_pcap(filepath)
            return render_template('pcap_contents.html', packets=packets)
    return render_template('upload_pcap.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pcap'

def read_pcap(filepath):
    """
    Reads a PCAP file and extracts information about packets.
    Returns a list of dictionaries containing packet summary.
    """
    packets = rdpcap(filepath)
    packet_summaries = []

    for packet in packets:
        summary = {
            'summary': packet.summary(),
            'timestamp': packet.time,
            'length': len(packet)
        }
        packet_summaries.append(summary)
    
    return packet_summaries

# Function to list all firewall rules using iptables (Linux example)
def list_firewall_rules():
    try:
        # Command to list all iptables rules
        command = "sudo iptables -L --line-numbers"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout  # Returns the iptables rules as a string
    except subprocess.CalledProcessError as e:
        return f"Error listing firewall rules: {str(e)}"

# Function to add a firewall rule
def add_firewall_rule(ip, port, protocol='tcp'):
    try:
        # Command to add a new rule to block traffic from a specific IP, port, and protocol
        command = f"sudo iptables -A INPUT -s {ip} -p {protocol} --dport {port} -j DROP"
        subprocess.run(command, shell=True, check=True)
        return f"Firewall rule added: Block {protocol.upper()} traffic from {ip} on port {port}."
    except subprocess.CalledProcessError as e:
        return f"Error adding firewall rule: {str(e)}"

# Function to remove a firewall rule
def remove_firewall_rule(ip, port, protocol='tcp'):
    try:
        # Command to remove a rule blocking traffic from a specific IP, port, and protocol
        command = f"sudo iptables -D INPUT -s {ip} -p {protocol} --dport {port} -j DROP"
        subprocess.run(command, shell=True, check=True)
        return f"Firewall rule removed: Allow {protocol.upper()} traffic from {ip} on port {port}."
    except subprocess.CalledProcessError as e:
        return f"Error removing firewall rule: {str(e)}"

# Firewall management route
@app.route('/firewall', methods=['GET', 'POST'])
def firewall():
    action_result = None
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip')
        port = request.form.get('port')
        protocol = request.form.get('protocol', 'tcp')

        if action == 'block':
            action_result = add_firewall_rule(ip, port, protocol)
        elif action == 'unblock':
            action_result = remove_firewall_rule(ip, port, protocol)

    rules = list_firewall_rules()
    return render_template('firewall.html', rules=rules, action_result=action_result)


@app.route('/live-data', methods=['GET'])
def get_live_data():
    with live_data_lock:
        return jsonify(list(live_data))

def update_live_data():
    max_logs = 25  # Define the maximum number of logs to keep
    while True:
        signal_strength = random.randint(-80, -50)
        with live_data_lock:
            # Append the new log
            live_data.append({'time': time.time(), 'signal_strength': signal_strength})
            # Check if we exceed the max number of logs
            if len(live_data) > max_logs:
                # Remove the oldest log
                live_data.pop(0)
        time.sleep(1)

threading.Thread(target=update_live_data, daemon=True).start()



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004)
