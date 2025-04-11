import psutil
import json
from datetime import datetime
import os

def get_system_metrics():
    try:
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()

        # Memory Usage
        memory = psutil.virtual_memory()

        # Disk Usage
        disk = psutil.disk_usage('/')

        # Network Stats
        net_io = psutil.net_io_counters()

        # Running Processes
        processes = [p.name() for p in psutil.process_iter()]

        # Get CPU temperature if available
        try:
            if os.name == 'nt':  # Windows
                import wmi
                w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
                temperature_infos = w.Sensor()
                for sensor in temperature_infos:
                    if sensor.SensorType == 'Temperature':
                        cpu_temp = sensor.Value
                        break
                else:
                    cpu_temp = None
            else:  # Linux
                temps = psutil.sensors_temperatures()
                cpu_temp = temps['coretemp'][0].current if 'coretemp' in temps else None
        except:
            cpu_temp = None

        # Create metrics dictionary
        metrics = {
            "cpu": {
                "usage": cpu_percent,
                "cores": cpu_count,
                "frequency": cpu_freq.current if cpu_freq else None,
                "temperature": cpu_temp
            },
            "memory": {
                "usage": memory.percent,
                "total": memory.total,
                "available": memory.available,
                "used": memory.used
            },
            "storage": {
                "usage": disk.percent,
                "total": disk.total,
                "available": disk.free,
                "used": disk.used
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_received": net_io.bytes_recv
            },
            "processes": processes[:10],  # Get first 10 processes
            "timestamp": datetime.now().isoformat()
        }

        # Print JSON data
        print(json.dumps(metrics))
        return metrics

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return None

if __name__ == "__main__":
    get_system_metrics()