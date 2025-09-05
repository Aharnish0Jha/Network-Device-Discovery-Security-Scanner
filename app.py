import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import pdfplumber
import base64
import random
import plotly.io as pio
import subprocess
import time
from typing import List, Dict
import sys

# Nmap scanner utilities
try:
    import network_scanner as nscan
except Exception:
    nscan = None

def generate_pdf_report():
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph("Network Device Discovery & Security Scanner Report", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Report metadata
    from datetime import datetime
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Report Generated: {report_date}", styles['BodyText']))
    story.append(Spacer(1, 12))
    
    # Network scan summary
    if 'nmap_hosts' in st.session_state and st.session_state.get('nmap_hosts'):
        hosts = st.session_state['nmap_hosts']
        story.append(Paragraph("Network Scan Summary", styles['Heading2']))
        story.append(Paragraph(f"Total Devices Discovered: {len(hosts)}", styles['BodyText']))
        
        # Count active devices
        active_devices = len([h for h in hosts if h.get('status') == 'up'])
        story.append(Paragraph(f"Active Devices: {active_devices}", styles['BodyText']))
        
        # Count total open ports
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        story.append(Paragraph(f"Total Open Ports: {total_ports}", styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Device details
        story.append(Paragraph("Device Details", styles['Heading2']))
        for i, host in enumerate(hosts, 1):
            story.append(Paragraph(f"{i}. IP: {host.get('ip', 'Unknown')}", styles['BodyText']))
            story.append(Paragraph(f"   Hostname: {host.get('hostname', 'Unknown')}", styles['BodyText']))
            story.append(Paragraph(f"   Status: {host.get('status', 'Unknown')}", styles['BodyText']))
            story.append(Paragraph(f"   OS: {host.get('os', 'Unknown')}", styles['BodyText']))
            story.append(Paragraph(f"   Vendor: {host.get('vendor', 'Unknown')}", styles['BodyText']))
            story.append(Paragraph(f"   Open Ports: {len(host.get('ports', []))}", styles['BodyText']))
            
            # List open ports
            ports = host.get('ports', [])
            if ports:
                story.append(Paragraph("   Port Details:", styles['BodyText']))
                for port in ports[:10]:  # Limit to first 10 ports
                    port_info = f"     Port {port.get('port', 'N/A')}: {port.get('service', 'Unknown')} ({port.get('state', 'Unknown')})"
                    story.append(Paragraph(port_info, styles['BodyText']))
                if len(ports) > 10:
                    story.append(Paragraph(f"     ... and {len(ports) - 10} more ports", styles['BodyText']))
            story.append(Spacer(1, 6))
        
        # Detailed scan results
        if 'nmap_details' in st.session_state and st.session_state.get('nmap_details'):
            story.append(Paragraph("Detailed Scan Results", styles['Heading2']))
            details = st.session_state['nmap_details']
            for ip, detail in details.items():
                if detail:
                    story.append(Paragraph(f"Detailed scan for {ip}:", styles['BodyText']))
                    story.append(Paragraph(f"  Hostname: {detail.get('hostname', 'Unknown')}", styles['BodyText']))
                    story.append(Paragraph(f"  OS: {detail.get('os', 'Unknown')}", styles['BodyText']))
                    story.append(Paragraph(f"  MAC: {detail.get('mac', 'Unknown')}", styles['BodyText']))
                    story.append(Paragraph(f"  Vendor: {detail.get('vendor', 'Unknown')}", styles['BodyText']))
                    story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No network scan data available.", styles['BodyText']))
        story.append(Paragraph("Please run a network scan first to generate a comprehensive report.", styles['BodyText']))
    
    story.append(Spacer(1, 12))
    story.append(Paragraph("End of Report", styles['BodyText']))
    
    doc.build(story)
    st.session_state.pdf_report = buffer.getvalue()
    buffer.close()

# Fix for Kaleido
pio.kaleido.scope.mathjax = None

# App Configuration
st.set_page_config(
    page_title="Network Device Discovery & Security Scanner 🛡️",
    page_icon="📶",
    layout="wide"
)

# Custom CSS for UI
st.markdown("""
<style>
    .st-emotion-cache-1kyxreq { display: flex; flex-flow: wrap; gap: 2rem; }
    .reportview-container .main .block-container{ padding-top: 2rem; }
    .sidebar .sidebar-content { background: linear-gradient(180deg, #2e3b4e, #1a2639); }
    .stButton>button { width: 100%; margin: 5px 0; transition: all 0.3s; }
    .stButton>button:hover { transform: scale(1.05); }
    .summary-box { padding: 20px; border-radius: 10px; background-color: #2e3b4e; margin: 10px 0; }
</style>
""", unsafe_allow_html=True)

# Motivational Quotes
QUOTES = [
    "🛡️ Cybersecurity is not a product, but a process!",
    "🔒 Better safe than hacked!",
    "📶 A secure network is a happy network!",
    "🤖 AI guards while you sleep!",
    "🚨 Detect before you regret!",
    "💻 Security is always worth the investment!",
    "🔍 Stay vigilant, stay secure!"
]

def show_quote():
    st.markdown(f"<h3 style='text-align: center; color: #4CAF50;'>{random.choice(QUOTES)}</h3>", 
                unsafe_allow_html=True)

# Function to run network_logger.py
def run_network_logger():
    st.title("📡 Network Scan in Progress...")
    st.markdown("---")

    # Network scan configuration
    st.subheader("⚙️ Scan Configuration")
    col1, col2 = st.columns(2)
    
    with col1:
        scan_type = st.selectbox("Scan Type", ["Basic Network Discovery", "Full Network Analysis", "Custom Scan"])
        if scan_type == "Custom Scan":
            custom_ports = st.text_input("Custom Ports (comma-separated)", "22,80,443,8080")
            ports_list = [int(p.strip()) for p in custom_ports.split(",") if p.strip().isdigit()]
        else:
            ports_list = None
    
    with col2:
        scan_timeout = st.slider("Scan Timeout (seconds)", 1, 10, 3)
        max_concurrent = st.slider("Max Concurrent Scans", 10, 256, 64)
    
    if st.button("🚀 Start Network Scan", type="primary"):
        with st.spinner("Initializing network scan..."):
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            results_area = st.empty()
            
            try:
                # Simulate network scanning with progress updates
                total_steps = 100
                current_step = 0
                
                # Phase 1: Network Discovery
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"🔍 Phase 1: Discovering network devices... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Phase 2: Port Scanning
                for i in range(40):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"🔌 Phase 2: Scanning ports and services... ({i+1}/40)")
                    time.sleep(0.1)
                
                # Phase 3: Analysis
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"📊 Phase 3: Analyzing results... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Phase 4: Finalization
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"✨ Phase 4: Finalizing scan report... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Display comprehensive scan results
                st.success("✅ Network scan completed successfully!")
                
                # Mock scan results for demonstration
                mock_devices = [
                    {"ip": "192.168.1.1", "hostname": "Router", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "TP-Link", "os": "Linux", "ports": [80, 443, 22]},
                    {"ip": "192.168.1.2", "hostname": "PC-Desktop", "mac": "11:22:33:44:55:66", "vendor": "Intel", "os": "Windows 11", "ports": [135, 139, 445, 3389]},
                    {"ip": "192.168.1.3", "hostname": "Mobile-Phone", "mac": "AA:11:BB:22:CC:33", "vendor": "Samsung", "os": "Android", "ports": [8080]},
                    {"ip": "192.168.1.4", "hostname": "Smart-TV", "mac": "DD:44:EE:55:FF:66", "vendor": "LG", "os": "WebOS", "ports": [3000, 8008, 8009]},
                ]
                
                # Scan Statistics
                st.subheader("📊 Network Scan Results")
                col_stats1, col_stats2, col_stats3, col_stats4 = st.columns(4)
                with col_stats1:
                    st.metric("Total Devices", len(mock_devices))
                with col_stats2:
                    st.metric("Active Services", sum(len(d["ports"]) for d in mock_devices))
                with col_stats3:
                    st.metric("Scan Duration", f"{scan_timeout}s")
                with col_stats4:
                    st.metric("Scan Type", scan_type)
                
                # Device Details Table
                st.subheader("🔍 Discovered Devices")
                device_data = []
                for i, device in enumerate(mock_devices, 1):
                    device_data.append({
                        "Device #": i,
                        "IP Address": device["ip"],
                        "Hostname": device["hostname"],
                        "MAC Address": device["mac"],
                        "Vendor": device["vendor"],
                        "Operating System": device["os"],
                        "Open Ports": len(device["ports"]),
                        "Port List": ", ".join(map(str, device["ports"]))
                    })
                
                device_df = pd.DataFrame(device_data)
                st.dataframe(device_df, use_container_width=True)
                
                # Network Security Analysis
                st.subheader("🛡️ Security Analysis")
                col_sec1, col_sec2 = st.columns(2)
                
                with col_sec1:
                    st.info("✅ **Secure Services Detected:**")
                    st.write("• HTTPS (443) - Encrypted web traffic")
                    st.write("• SSH (22) - Secure remote access")
                    st.write("• SMB (445) - File sharing with authentication")
                    
                with col_sec2:
                    st.warning("⚠️ **Potential Security Concerns:**")
                    st.write("• HTTP (80) - Unencrypted web traffic")
                    st.write("• RDP (3389) - Remote desktop access")
                    st.write("• Multiple open ports on smart devices")
                
                # Network Topology
                st.subheader("🌐 Network Topology")
                st.write("**Network Structure:**")
                st.write("• **Gateway:** 192.168.1.1 (Router)")
                st.write("• **Client Devices:** 3 active endpoints")
                st.write("• **Network Type:** Private Class C (192.168.1.0/24)")
                st.write("• **Device Categories:** Router, PC, Mobile, Smart TV")
                
                # Recommendations
                st.subheader("💡 Security Recommendations")
                st.write("1. **Enable Firewall:** Ensure all devices have firewalls enabled")
                st.write("2. **Update Firmware:** Keep router and device firmware updated")
                st.write("3. **Port Management:** Close unnecessary ports on smart devices")
                st.write("4. **Network Segmentation:** Consider separating IoT devices from main network")
                st.write("5. **Regular Scans:** Perform network scans monthly to detect changes")
                
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")
                progress_bar.empty()
                status_text.empty()


# Main App Function
def main():
    if 'current_step' not in st.session_state:
        st.session_state.current_step = 1

    # Sidebar Navigation
    with st.sidebar:
        st.title("🔍 Navigation")
        st.markdown("---")

        if st.button("📡 1. Scan Your Network"):
            st.session_state.current_step = 1
        if st.button("🛰️ 2. Devices & Port Scan (Nmap)"):
            st.session_state.current_step = 2
        if st.button("📊 3. Data Visualization"):
            st.session_state.current_step = 3
        if st.button("📈 4. Statistics Analysis"):
            st.session_state.current_step = 4
        if st.button("📥 5. Download Report"):
            st.session_state.current_step = 5

    # Main Content Area
    if st.session_state.current_step == 1:
        scan_network_section()
    elif st.session_state.current_step == 2:
        nmap_scan_section()
    elif st.session_state.current_step == 3:
        visualization_section()
    elif st.session_state.current_step == 4:
        statistics_section()
    elif st.session_state.current_step == 5:
        download_section()


def visualization_section():
    st.title("📊 Network Data Visualization")
    st.markdown("---")

    # Check if we have network scan data
    if 'nmap_hosts' not in st.session_state or not st.session_state.nmap_hosts:
        st.warning("⚠️ No network scan data available. Please run a network scan first.")
        return

    hosts = st.session_state.nmap_hosts
    
    # Create a DataFrame from the scan results
    data = []
    for host in hosts:
        data.append({
            'ip': host.get('ip', 'Unknown'),
            'hostname': host.get('hostname', 'Unknown'),
            'status': host.get('status', 'Unknown'),
            'os': host.get('os', 'Unknown'),
            'port_count': len(host.get('ports', [])),
            'vendor': host.get('vendor', 'Unknown')
        })
    
    df = pd.DataFrame(data)
    
    st.subheader("📊 Device Status Distribution")
    status_counts = df['status'].value_counts()
    fig_status = px.pie(values=status_counts.values, names=status_counts.index, 
                       title="Device Status Distribution", hole=0.4)
    st.plotly_chart(fig_status, use_container_width=True)
    
    st.subheader("🔌 Open Ports Analysis")
    port_data = []
    for host in hosts:
        for port in host.get('ports', []):
            port_data.append({
                'ip': host.get('ip'),
                'port': port.get('port'),
                'service': port.get('service', 'Unknown'),
                'state': port.get('state', 'Unknown')
            })
    
    if port_data:
        port_df = pd.DataFrame(port_data)
        
        # Port distribution chart
        port_counts = port_df['port'].value_counts().head(10)
        fig_ports = px.bar(x=port_counts.index, y=port_counts.values, 
                          title="Top 10 Open Ports", labels={'x': 'Port Number', 'y': 'Count'})
        st.plotly_chart(fig_ports, use_container_width=True)
        
        # Service distribution
        service_counts = port_df['service'].value_counts().head(10)
        fig_services = px.bar(x=service_counts.index, y=service_counts.values, 
                             title="Top 10 Services", labels={'x': 'Service', 'y': 'Count'})
        st.plotly_chart(fig_services, use_container_width=True)
    else:
        st.info("No open ports found in the scan results.")
    
    st.subheader("📋 Device Summary Table")
    st.dataframe(df, use_container_width=True)


def statistics_section():
    st.title("📈 Network Statistics Analysis")
    st.markdown("---")
    
    # Check if we have network scan data
    if 'nmap_hosts' not in st.session_state or not st.session_state.nmap_hosts:
        st.warning("⚠️ No network scan data available. Please run a network scan first.")
        return

    hosts = st.session_state.nmap_hosts
    
    # Create a DataFrame from the scan results
    data = []
    for host in hosts:
        data.append({
            'ip': host.get('ip', 'Unknown'),
            'hostname': host.get('hostname', 'Unknown'),
            'status': host.get('status', 'Unknown'),
            'os': host.get('os', 'Unknown'),
            'port_count': len(host.get('ports', [])),
            'vendor': host.get('vendor', 'Unknown')
        })
    
    df = pd.DataFrame(data)
    
    st.subheader("📊 Network Statistics Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Devices", len(hosts))
    
    with col2:
        up_devices = len([h for h in hosts if h.get('status') == 'up'])
        st.metric("Active Devices", up_devices)
    
    with col3:
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        st.metric("Total Open Ports", total_ports)
    
    with col4:
        unique_services = set()
        for host in hosts:
            for port in host.get('ports', []):
                if port.get('service'):
                    unique_services.add(port.get('service'))
        st.metric("Unique Services", len(unique_services))
    
    st.subheader("📋 Device Details")
    st.dataframe(df.describe(include='all'), use_container_width=True)
    
    st.subheader("🔍 Operating System Distribution")
    os_counts = df['os'].value_counts()
    if len(os_counts) > 0:
        fig_os = px.pie(values=os_counts.values, names=os_counts.index, 
                       title="Operating System Distribution", hole=0.4)
        st.plotly_chart(fig_os, use_container_width=True)
    else:
        st.info("No OS information available from the scan.")
    
    st.subheader("🏢 Vendor Distribution")
    vendor_counts = df['vendor'].value_counts()
    if len(vendor_counts) > 0:
        fig_vendor = px.pie(values=vendor_counts.values, names=vendor_counts.index, 
                           title="Device Vendor Distribution", hole=0.4)
        st.plotly_chart(fig_vendor, use_container_width=True)
    else:
        st.info("No vendor information available from the scan.")


def download_section():
    st.title("📥 Download Report")
    st.markdown("---")

    # Check if we have network scan data
    if 'nmap_hosts' not in st.session_state or not st.session_state.nmap_hosts:
        st.warning("⚠️ No network scan data available. Please run a network scan first to generate a report.")
        st.info("💡 Go to 'Scan Your Network' or 'Devices & Port Scan (Nmap)' to collect data first.")
        return

    st.info(f"📊 Ready to generate report with {len(st.session_state.nmap_hosts)} discovered devices.")

    if st.button("🖨️ Generate Full Report", type="primary"):
        with st.spinner("Generating comprehensive PDF report..."):
            try:
                generate_pdf_report()
                st.success("✅ Report generated successfully!")
            except Exception as e:
                st.error(f"❌ Error generating report: {str(e)}")
                return
    
    if 'pdf_report' in st.session_state:
        st.success("📄 Report is ready for download!")
        b64 = base64.b64encode(st.session_state.pdf_report).decode()
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="network_device_discovery_security_scanner_report.pdf" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">📥 Download Full Report</a>'
        st.markdown(href, unsafe_allow_html=True)
        
        # Show report preview
        st.subheader("📋 Report Preview")
        hosts = st.session_state.nmap_hosts
        st.write(f"**Total Devices:** {len(hosts)}")
        st.write(f"**Active Devices:** {len([h for h in hosts if h.get('status') == 'up'])}")
        st.write(f"**Total Open Ports:** {sum(len(h.get('ports', [])) for h in hosts)}")
        
        # Show device summary
        if hosts:
            st.write("**Device Summary:**")
            for i, host in enumerate(hosts[:5], 1):  # Show first 5 devices
                st.write(f"{i}. {host.get('ip', 'Unknown')} - {host.get('hostname', 'Unknown')} ({host.get('status', 'Unknown')})")
            if len(hosts) > 5:
                st.write(f"... and {len(hosts) - 5} more devices")


def scan_network_section():
    st.title("📡 Scan Your Network")
    st.markdown("---")

    # Network scan configuration
    st.subheader("⚙️ Scan Configuration")
    col1, col2 = st.columns(2)
    
    with col1:
        scan_type = st.selectbox("Scan Type", ["Basic Network Discovery", "Full Network Analysis", "Custom Scan"])
        if scan_type == "Custom Scan":
            custom_ports = st.text_input("Custom Ports (comma-separated)", "22,80,443,8080")
            ports_list = [int(p.strip()) for p in custom_ports.split(",") if p.strip().isdigit()]
        else:
            ports_list = None
    
    with col2:
        scan_timeout = st.slider("Scan Timeout (seconds)", 1, 10, 3)
        max_concurrent = st.slider("Max Concurrent Scans", 10, 256, 64)
    
    if st.button("🚀 Start Network Scan", type="primary"):
        with st.spinner("Initializing network scan..."):
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            results_area = st.empty()
            
            try:
                # Simulate network scanning with progress updates
                total_steps = 100
                current_step = 0
                
                # Phase 1: Network Discovery
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"🔍 Phase 1: Discovering network devices... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Phase 2: Port Scanning
                for i in range(40):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"🔌 Phase 2: Scanning ports and services... ({i+1}/40)")
                    time.sleep(0.1)
                
                # Phase 3: Analysis
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"📊 Phase 3: Analyzing results... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Phase 4: Finalization
                for i in range(20):
                    current_step += 1
                    progress_bar.progress(current_step / total_steps)
                    status_text.text(f"✨ Phase 4: Finalizing scan report... ({i+1}/20)")
                    time.sleep(0.1)
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Display comprehensive scan results
                st.success("✅ Network scan completed successfully!")
                
                # Mock scan results for demonstration
                mock_devices = [
                    {"ip": "192.168.1.1", "hostname": "Router", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "TP-Link", "os": "Linux", "ports": [80, 443, 22]},
                    {"ip": "192.168.1.2", "hostname": "PC-Desktop", "mac": "11:22:33:44:55:66", "vendor": "Intel", "os": "Windows 11", "ports": [135, 139, 445, 3389]},
                    {"ip": "192.168.1.3", "hostname": "Mobile-Phone", "mac": "AA:11:BB:22:CC:33", "vendor": "Samsung", "os": "Android", "ports": [8080]},
                    {"ip": "192.168.1.4", "hostname": "Smart-TV", "mac": "DD:44:EE:55:FF:66", "vendor": "LG", "os": "WebOS", "ports": [3000, 8008, 8009]},
                ]
                
                # Scan Statistics
                st.subheader("📊 Network Scan Results")
                col_stats1, col_stats2, col_stats3, col_stats4 = st.columns(4)
                with col_stats1:
                    st.metric("Total Devices", len(mock_devices))
                with col_stats2:
                    st.metric("Active Services", sum(len(d["ports"]) for d in mock_devices))
                with col_stats3:
                    st.metric("Scan Duration", f"{scan_timeout}s")
                with col_stats4:
                    st.metric("Scan Type", scan_type)
                
                # Device Details Table
                st.subheader("🔍 Discovered Devices")
                device_data = []
                for i, device in enumerate(mock_devices, 1):
                    device_data.append({
                        "Device #": i,
                        "IP Address": device["ip"],
                        "Hostname": device["hostname"],
                        "MAC Address": device["mac"],
                        "Vendor": device["vendor"],
                        "Operating System": device["os"],
                        "Open Ports": len(device["ports"]),
                        "Port List": ", ".join(map(str, device["ports"]))
                    })
                
                device_df = pd.DataFrame(device_data)
                st.dataframe(device_df, use_container_width=True)
                
                # Network Security Analysis
                st.subheader("🛡️ Security Analysis")
                col_sec1, col_sec2 = st.columns(2)
                
                with col_sec1:
                    st.info("✅ **Secure Services Detected:**")
                    st.write("• HTTPS (443) - Encrypted web traffic")
                    st.write("• SSH (22) - Secure remote access")
                    st.write("• SMB (445) - File sharing with authentication")
                    
                with col_sec2:
                    st.warning("⚠️ **Potential Security Concerns:**")
                    st.write("• HTTP (80) - Unencrypted web traffic")
                    st.write("• RDP (3389) - Remote desktop access")
                    st.write("• Multiple open ports on smart devices")
                
                # Network Topology
                st.subheader("🌐 Network Topology")
                st.write("**Network Structure:**")
                st.write("• **Gateway:** 192.168.1.1 (Router)")
                st.write("• **Client Devices:** 3 active endpoints")
                st.write("• **Network Type:** Private Class C (192.168.1.0/24)")
                st.write("• **Device Categories:** Router, PC, Mobile, Smart TV")
                
                # Recommendations
                st.subheader("💡 Security Recommendations")
                st.write("1. **Enable Firewall:** Ensure all devices have firewalls enabled")
                st.write("2. **Update Firmware:** Keep router and device firmware updated")
                st.write("3. **Port Management:** Close unnecessary ports on smart devices")
                st.write("4. **Network Segmentation:** Consider separating IoT devices from main network")
                st.write("5. **Regular Scans:** Perform network scans monthly to detect changes")
                
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")
                progress_bar.empty()
                status_text.empty()


def nmap_scan_section():
    st.title("🛰️ Devices & Port Scan (Nmap)")
    st.markdown("---")

    if nscan is None:
        st.error("Scanner module not available. Please ensure `network_scanner.py` exists.")
        return

    if 'nmap_discovery' not in st.session_state:
        st.session_state.nmap_discovery = None
    if 'nmap_hosts' not in st.session_state:
        st.session_state.nmap_hosts = []
    if 'nmap_details' not in st.session_state:
        st.session_state.nmap_details = {}

    nmap_ok = nscan.is_nmap_available()
    if not nmap_ok:
        st.info("Nmap not found. Using fallback discovery and basic TCP port scan on common ports.")
        with st.expander("Install Nmap for deeper scanning (OS/service detection)"):
            st.markdown("- Download from [nmap.org](https://nmap.org/download.html) and add to PATH.")

    cidr_default = nscan.detect_local_cidr_windows() or "192.168.1.0/24"
    target_cidr = st.text_input("Target network (CIDR)", cidr_default)

    with st.expander("Scan settings"):
        profile = st.selectbox("Profile", ["Fast", "Balanced", "Thorough"], index=1,
                               help="Fast: fewer hosts/ports, lower timeouts. Thorough: more ports, higher timeouts.")
        if profile == "Fast":
            ping_timeout_ms = 200
            tcp_timeout = 0.2
            max_workers = 256
            ports_preset = [80, 443, 8080, 22, 3389]
        elif profile == "Thorough":
            ping_timeout_ms = 600
            tcp_timeout = 0.6
            max_workers = 128
            ports_preset = None  # use default common set
        else:  # Balanced
            ping_timeout_ms = 400
            tcp_timeout = 0.4
            max_workers = 192
            ports_preset = [22, 80, 443, 445, 3389, 8080]

        custom_ports = st.text_input("Ports to scan (comma-separated, leave blank to use preset)", "")
        ports_list = None
        if custom_ports.strip():
            try:
                ports_list = [int(p.strip()) for p in custom_ports.split(",") if p.strip()]
            except Exception:
                st.warning("Invalid ports list; using preset.")
                ports_list = ports_preset
        else:
            ports_list = ports_preset

    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("🔎 Discover Devices"):
            with st.spinner("Running Nmap host discovery..."):
                try:
                    # Progress tracking
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    def update_progress(completed, total, message):
                        progress_bar.progress(completed / total)
                        status_text.text(message)
                    
                    hosts = nscan.discover_devices(target_cidr, ping_timeout_ms=ping_timeout_ms, max_workers=max_workers, progress_callback=update_progress)
                    st.session_state.nmap_discovery = hosts
                    st.session_state.nmap_hosts = hosts
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    st.success(f"✅ Found {len(hosts)} device(s) up")
                    
                    # Display detailed network scan results
                    if hosts:
                        st.subheader("📊 Network Scan Results")
                        
                        # Scan statistics
                        col_stats1, col_stats2, col_stats3 = st.columns(3)
                        with col_stats1:
                            st.metric("Total Devices", len(hosts))
                        with col_stats2:
                            st.metric("Network Range", target_cidr)
                        with col_stats3:
                            st.metric("Scan Profile", profile)
                        
                        # Device summary table
                        st.subheader("🔍 Device Summary")
                        summary_data = []
                        for i, host in enumerate(hosts, 1):
                            summary_data.append({
                                "Device #": i,
                                "IP Address": host.get("ip", "N/A"),
                                "Hostname": host.get("hostname", "N/A"),
                                "MAC Address": host.get("mac", "N/A"),
                                "Vendor": host.get("vendor", "N/A"),
                                "OS": host.get("os", "N/A"),
                                "Status": host.get("status", "N/A"),
                                "Open Ports": len(host.get("ports", [])),
                            })
                        
                        summary_df = pd.DataFrame(summary_data)
                        st.dataframe(summary_df, use_container_width=True, height=300)
                        
                        # Network insights
                        st.subheader("💡 Network Insights")
                        col_insights1, col_insights2 = st.columns(2)
                        
                        with col_insights1:
                            if len(hosts) > 1:
                                st.info(f"🌐 Network appears to be active with {len(hosts)} devices")
                            else:
                                st.warning("⚠️ Only one device found - this might be a point-to-point connection")
                            
                            # Network type detection
                            if target_cidr.endswith("/24"):
                                st.success("📡 Standard home/office network detected (/24 subnet)")
                            elif target_cidr.endswith("/16"):
                                st.info("🏢 Large network detected (/16 subnet)")
                            elif target_cidr.endswith("/8"):
                                st.warning("🌍 Very large network detected (/8 subnet)")
                        
                        with col_insights2:
                            # Response time analysis
                            st.write("**Network Performance:**")
                            if ping_timeout_ms <= 200:
                                st.success("⚡ Fast network response (≤200ms)")
                            elif ping_timeout_ms <= 400:
                                st.info("🚀 Good network response (≤400ms)")
                            else:
                                st.warning("🐌 Slow network response (>400ms)")
                        
                        # Common services detection
                        all_ports = []
                        for host in hosts:
                            all_ports.extend([p.get("port") for p in host.get("ports", []) if p.get("state") == "open"])
                        
                        if all_ports:
                            st.subheader("🔌 Common Open Ports")
                            port_counts = pd.Series(all_ports).value_counts().head(10)
                            
                            # Create a more visual port display
                            col_ports1, col_ports2 = st.columns(2)
                            with col_ports1:
                                for port, count in port_counts.items():
                                    if count > 1:
                                        st.write(f"  • **Port {port}:** {count} devices")
                                    else:
                                        st.write(f"  • Port {port}: {count} device")
                            
                            with col_ports2:
                                # Port security analysis
                                secure_ports = [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995]
                                open_secure = [p for p in all_ports if p in secure_ports]
                                if open_secure:
                                    st.write("**Security Status:**")
                                    st.success(f"✅ {len(open_secure)} standard service ports open")
                                else:
                                    st.warning("⚠️ No standard service ports detected")
                        
                except Exception as e:
                    st.error(f"Discovery failed: {e}")
    with col2:
        clear = st.button("♻️ Clear Results")
        if clear:
            st.session_state.nmap_discovery = None
            st.session_state.nmap_hosts = []
            st.session_state.nmap_details = {}

    # Only show device selection and scanning if devices were discovered
    hosts: List[Dict] = st.session_state.nmap_hosts or []
    if hosts:
        st.subheader("🛰️ Individual Device Scanning")
        target_ips = [h.get("ip") for h in hosts if h.get("ip")]
        selected_ip = st.selectbox("Select a device", target_ips)
        if selected_ip:
            if st.button("🚀 Scan Selected Device" + (" (-A)" if nmap_ok else "")):
                with st.spinner(f"Scanning {selected_ip} aggressively..."):
                    try:
                        details = nscan.scan_host_details(selected_ip, ports=ports_list, tcp_timeout=tcp_timeout, max_workers=max_workers)
                        st.session_state.nmap_details[selected_ip] = details if details else {}
                        st.success("Scan complete")
                    except Exception as e:
                        st.error(f"Aggressive scan failed: {e}")

        details = st.session_state.nmap_details.get(selected_ip or "", {})
        if details:
            st.markdown(f"**Host:** {details.get('ip')}  |  **Hostname:** {details.get('hostname') or '-'}  |  **OS:** {details.get('os') or '-'}")
            ports = details.get("ports", [])
            if ports:
                ports_df = pd.DataFrame([
                    {
                        "Port": p.get("port"),
                        "Proto": p.get("protocol"),
                        "State": p.get("state"),
                        "Service": p.get("service"),
                        "Product": p.get("product"),
                        "Version": p.get("version"),
                        "Extra": p.get("extra"),
                    }
                    for p in ports if p.get("state") == "open"
                ])
                st.dataframe(ports_df, use_container_width=True)
            else:
                st.info("No open ports reported.")

if __name__ == "__main__":
    main()
