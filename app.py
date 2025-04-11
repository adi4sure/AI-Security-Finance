from flask import Flask, jsonify
import psutil
import json
from datetime import datetime
import os
import subprocess
import re

app = Flask(__name__)

def get_system_metrics():
    try:
        # Run systemch.py and capture its output
        result = subprocess.run(['python', 'systemch.py'], capture_output=True, text=True)
        output = result.stdout
        
        # Parse the output
        metrics = {}
        for line in output.split('\n'):
            if 'CPU Usage:' in line:
                metrics['cpu_usage'] = float(re.search(r'(\d+\.?\d*)%', line).group(1))
            elif 'Memory Usage:' in line:
                metrics['memory_usage'] = float(re.search(r'(\d+\.?\d*)%', line).group(1))
            elif 'Disk Usage:' in line:
                metrics['disk_usage'] = float(re.search(r'(\d+\.?\d*)%', line).group(1))
            elif 'Bytes Sent:' in line:
                metrics['bytes_sent'] = int(re.search(r'Bytes Sent: (\d+)', line).group(1))
                metrics['bytes_received'] = int(re.search(r'Bytes Received: (\d+)', line).group(1))
            elif 'Running Processes:' in line:
                metrics['processes'] = eval(line.split(': ')[1])
        
        # Get additional metrics using psutil
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "cpu": {
                "usage": metrics.get('cpu_usage', 0),
                "cores": cpu_count,
                "frequency": cpu_freq.current if cpu_freq else None,
                "temperature": get_cpu_temperature()
            },
            "memory": {
                "usage": metrics.get('memory_usage', 0),
                "total": memory.total,
                "available": memory.available,
                "used": memory.used
            },
            "storage": {
                "usage": metrics.get('disk_usage', 0),
                "total": disk.total,
                "available": disk.free,
                "used": disk.used
            },
            "network": {
                "bytes_sent": metrics.get('bytes_sent', 0),
                "bytes_received": metrics.get('bytes_received', 0)
            },
            "processes": metrics.get('processes', []),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error getting system metrics: {e}")
        return None

def get_cpu_temperature():
    try:
        if os.name == 'nt':  # Windows
            import wmi
            w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
            temperature_infos = w.Sensor()
            for sensor in temperature_infos:
                if sensor.SensorType == 'Temperature':
                    return sensor.Value
        else:  # Linux
            temps = psutil.sensors_temperatures()
            if 'coretemp' in temps:
                return temps['coretemp'][0].current
    except:
        return None

def get_security_status():
    try:
        # Check if Windows Defender is running
        if os.name == 'nt':
            import wmi
            w = wmi.WMI()
            defender_running = False
            for service in w.Win32_Service(Name="WinDefend"):
                defender_running = service.State == "Running"
        else:
            defender_running = False

        # Check firewall status
        if os.name == 'nt':
            firewall_running = False
            for service in w.Win32_Service(Name="MpsSvc"):
                firewall_running = service.State == "Running"
        else:
            firewall_running = False

        return {
            "securityLevel": calculate_security_level(defender_running, firewall_running),
            "activeAlerts": 0,
            "firewall": firewall_running,
            "antivirus": defender_running,
            "encryption": True,
            "lastScan": datetime.now().isoformat(),
            "threatsDetected": 0
        }
    except Exception as e:
        print(f"Error getting security status: {e}")
        return None

def calculate_security_level(defender_running, firewall_running):
    base_level = 50
    if defender_running:
        base_level += 25
    if firewall_running:
        base_level += 25
    return base_level

@app.route('/api/system/metrics')
def system_metrics():
    metrics = get_system_metrics()
    if metrics:
        return jsonify(metrics)
    else:
        return jsonify({"error": "Failed to get system metrics"}), 500

@app.route('/api/security/status')
def security_status():
    status = get_security_status()
    if status:
        return jsonify(status)
    else:
        return jsonify({"error": "Failed to get security status"}), 500

@app.route('/api/system/activities')
def system_activities():
    metrics = get_system_metrics()
    security = get_security_status()
    
    activities = []
    
    if metrics:
        # Add CPU activity
        if metrics['cpu']['usage'] > 80:
            activities.append({
                "type": "warning",
                "title": "High CPU Usage",
                "description": f"CPU usage is at {metrics['cpu']['usage']}%",
                "timestamp": metrics['timestamp'],
                "severity": "warning"
            })
        
        # Add Memory activity
        if metrics['memory']['usage'] > 80:
            activities.append({
                "type": "warning",
                "title": "High Memory Usage",
                "description": f"Memory usage is at {metrics['memory']['usage']}%",
                "timestamp": metrics['timestamp'],
                "severity": "warning"
            })
    
    if security:
        # Add Security activities
        if not security['antivirus']:
            activities.append({
                "type": "threat",
                "title": "Antivirus Disabled",
                "description": "Windows Defender is not running",
                "timestamp": security['lastScan'],
                "severity": "threat"
            })
        
        if not security['firewall']:
            activities.append({
                "type": "threat",
                "title": "Firewall Disabled",
                "description": "Windows Firewall is not running",
                "timestamp": security['lastScan'],
                "severity": "threat"
            })
    
    return jsonify({"activities": activities})

if __name__ == '__main__':
    app.run(debug=True, port=5000) 