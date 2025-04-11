import asyncio
import websockets
import json
import os
import time
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional

class ScanServer:
    def __init__(self):
        self.clients = set()
        self.scanning = False
        self.current_progress = 0

    async def register(self, websocket):
        self.clients.add(websocket)
        print(f"New connection! ({id(websocket)})")

    async def unregister(self, websocket):
        self.clients.remove(websocket)
        print(f"Connection {id(websocket)} has disconnected")

    async def broadcast(self, message):
        if self.clients:
            await asyncio.gather(
                *[client.send(message) for client in self.clients]
            )

    async def handle_message(self, websocket, message):
        try:
            data = json.loads(message)
            if data['type'] == 'start_scan':
                await self.start_scan(data['scanType'], data['scanTarget'])
        except Exception as e:
            print(f"Error handling message: {e}")

    async def start_scan(self, scan_type: str, scan_target: str):
        if self.scanning:
            return

        self.scanning = True
        self.current_progress = 0

        # Define scan paths based on scan type
        scan_paths = {
            'quick': [os.path.join(os.environ['SystemRoot'], 'System32')],
            'full': [
                os.environ['SystemRoot'],
                os.path.join(os.environ['ProgramFiles']),
                os.path.join(os.environ['ProgramFiles(x86)'])
            ],
            'custom': [scan_target]
        }

        total_files = 0
        scanned_files = 0
        threats = []

        # Count total files first
        for path in scan_paths[scan_type]:
            total_files += await self.count_files(path)

        # Perform the scan
        for path in scan_paths[scan_type]:
            await self.scan_directory(path, scan_type, scanned_files, total_files, threats)

        self.scanning = False
        await self.broadcast(json.dumps({
            'type': 'scan_complete',
            'results': {
                'scanType': scan_type,
                'scanTarget': scan_target,
                'filesScanned': scanned_files,
                'threats': threats,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        }))

    async def count_files(self, path: str) -> int:
        count = 0
        try:
            for root, _, files in os.walk(path):
                count += len(files)
        except Exception as e:
            print(f"Error counting files in {path}: {e}")
        return count

    async def scan_directory(self, path: str, scan_type: str, scanned_files: int, total_files: int, threats: List[Dict]):
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    progress = round((scanned_files / total_files) * 100)

                    if progress > self.current_progress:
                        self.current_progress = progress
                        await self.broadcast(json.dumps({
                            'type': 'progress',
                            'progress': progress,
                            'status': self.get_status_message(progress)
                        }))

                    threat = await self.check_for_threats(file_path, scan_type)
                    if threat:
                        threats.append(threat)
                        await self.broadcast(json.dumps({
                            'type': 'threat_found',
                            'threat': threat
                        }))
        except Exception as e:
            print(f"Error scanning directory {path}: {e}")

    async def check_for_threats(self, file_path: str, scan_type: str) -> Optional[Dict]:
        try:
            file_extension = os.path.splitext(file_path)[1].lower()[1:]
            
            # Common threat indicators
            threat_indicators = {
                'exe': ['executable', 'binary'],
                'dll': ['library', 'binary'],
                'bat': ['batch', 'script'],
                'vbs': ['script', 'visual basic'],
                'js': ['javascript', 'script'],
                'py': ['python', 'script'],
                'ps1': ['powershell', 'script']
            }

            # Suspicious patterns
            suspicious_patterns = [
                r'eval\s*\(',
                r'base64_decode\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec\s*\(',
                r'passthru\s*\(',
                r'Invoke-Expression',
                r'Start-Process',
                r'New-Object'
            ]

            # Check file extension
            if file_extension in threat_indicators:
                return {
                    'id': f'threat-{hashlib.md5(file_path.encode()).hexdigest()}',
                    'name': os.path.basename(file_path),
                    'type': threat_indicators[file_extension][0],
                    'severity': 'medium',
                    'location': file_path,
                    'description': f'Potential {threat_indicators[file_extension][1]} file detected',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }

            # Check file content for suspicious patterns
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in suspicious_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return {
                                'id': f'threat-{hashlib.md5(file_path.encode()).hexdigest()}',
                                'name': os.path.basename(file_path),
                                'type': 'Suspicious Code',
                                'severity': 'high',
                                'location': file_path,
                                'description': 'Suspicious code pattern detected',
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
            except Exception:
                pass

        except Exception as e:
            print(f"Error checking threats in {file_path}: {e}")
        
        return None

    def get_status_message(self, progress: int) -> str:
        if progress < 30:
            return 'Scanning system files...'
        elif progress < 60:
            return 'Analyzing memory...'
        elif progress < 90:
            return 'Checking registry...'
        else:
            return 'Finalizing scan...'

async def main():
    server = ScanServer()
    
    async def handler(websocket, path):
        await server.register(websocket)
        try:
            async for message in websocket:
                await server.handle_message(websocket, message)
        finally:
            await server.unregister(websocket)

    async with websockets.serve(handler, "localhost", 5050):
        print("WebSocket server started on ws://localhost:5050")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main()) 