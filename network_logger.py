import csv
import time
import psutil
import subprocess
from datetime import datetime

# Define the output CSV file
csv_filename = "network_log.csv"

# Function to get network traffic (upload/download speed)
def get_network_traffic():
    net_io1 = psutil.net_io_counters()
    time.sleep(1)  # Measure over 1 second
    net_io2 = psutil.net_io_counters()

    download_speed = (net_io2.bytes_recv - net_io1.bytes_recv) / 1024  # KB/s
    upload_speed = (net_io2.bytes_sent - net_io1.bytes_sent) / 1024  # KB/s
    return round(download_speed, 2), round(upload_speed, 2)

# Function to get latency (ping response time) and packet loss
def get_network_latency():
    try:
        # Run ping command (Windows/Linux compatible)
        ping_output = subprocess.run(
            ["ping", "-c", "4", "8.8.8.8"], capture_output=True, text=True
        ).stdout
        
        # Extract latency from ping output
        latency_lines = [line for line in ping_output.split("\n") if "time=" in line]
        latencies = [float(line.split("time=")[1].split(" ms")[0]) for line in latency_lines]
        
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0
        
        # Calculate packet loss percentage
        loss_line = [line for line in ping_output.split("\n") if "packet loss" in line]
        packet_loss = 0
        if loss_line:
            packet_loss = int(loss_line[0].split(",")[2].split("%")[0])
        
        return avg_latency, packet_loss
    
    except Exception as e:
        return 0, 0

# Initialize CSV file with headers if it does not exist
with open(csv_filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["timestamp", "traffic", "latency", "packet_loss"])

print("Packets are being captured... Press CTRL+C to stop.")

# Main loop to log network data
try:
    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        download_speed, upload_speed = get_network_traffic()
        latency, packet_loss = get_network_latency()
        
        # Formatting traffic data as "Download/Upload KBps"
        traffic = f"{download_speed}/{upload_speed} KBps"
        
        # Append data to CSV
        with open(csv_filename, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, traffic, latency, packet_loss])
        
        # Show minimal output in terminal
        print("Packets are being captured...", end="\r", flush=True)

        time.sleep(5)  # Adjust frequency of logging as needed

except KeyboardInterrupt:
    print("\nNetwork logging stopped.")
