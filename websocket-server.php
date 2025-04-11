<?php
require 'vendor/autoload.php';

use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;
use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;

class ScanServer implements MessageComponentInterface {
    protected $clients;
    protected $scanning = false;
    protected $currentProgress = 0;

    public function __construct() {
        $this->clients = new \SplObjectStorage;
    }

    public function onOpen(ConnectionInterface $conn) {
        $this->clients->attach($conn);
        echo "New connection! ({$conn->resourceId})\n";
    }

    public function onMessage(ConnectionInterface $from, $msg) {
        $data = json_decode($msg, true);
        
        if ($data['type'] === 'start_scan') {
            $this->startScan($data['scanType'], $data['scanTarget']);
        }
    }

    public function onClose(ConnectionInterface $conn) {
        $this->clients->detach($conn);
        echo "Connection {$conn->resourceId} has disconnected\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e) {
        echo "An error has occurred: {$e->getMessage()}\n";
        $conn->close();
    }

    protected function startScan($scanType, $scanTarget) {
        if ($this->scanning) {
            return;
        }

        $this->scanning = true;
        $this->currentProgress = 0;

        // Define scan paths based on scan type
        $scanPaths = [
            'quick' => ['C:\\Windows\\System32'],
            'full' => ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)'],
            'custom' => [$scanTarget]
        ];

        $totalFiles = 0;
        $scannedFiles = 0;
        $threats = [];

        // Count total files first
        foreach ($scanPaths[$scanType] as $path) {
            $totalFiles += $this->countFiles($path);
        }

        // Perform the scan
        foreach ($scanPaths[$scanType] as $path) {
            $this->scanDirectory($path, $scanType, $scannedFiles, $totalFiles, $threats);
        }

        $this->scanning = false;
        $this->sendToAll(json_encode([
            'type' => 'scan_complete',
            'results' => [
                'scanType' => $scanType,
                'scanTarget' => $scanTarget,
                'filesScanned' => $scannedFiles,
                'threats' => $threats,
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]));
    }

    protected function countFiles($path) {
        $count = 0;
        if (is_dir($path)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $count++;
                }
            }
        }
        return $count;
    }

    protected function scanDirectory($path, $scanType, &$scannedFiles, $totalFiles, &$threats) {
        if (!is_dir($path)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $scannedFiles++;
                $progress = round(($scannedFiles / $totalFiles) * 100);
                
                if ($progress > $this->currentProgress) {
                    $this->currentProgress = $progress;
                    $this->sendToAll(json_encode([
                        'type' => 'progress',
                        'progress' => $progress,
                        'status' => $this->getStatusMessage($progress)
                    ]));
                }

                $threat = $this->checkForThreats($file->getPathname(), $scanType);
                if ($threat) {
                    $threats[] = $threat;
                    $this->sendToAll(json_encode([
                        'type' => 'threat_found',
                        'threat' => $threat
                    ]));
                }
            }
        }
    }

    protected function checkForThreats($filePath, $scanType) {
        $fileExtension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $fileContent = @file_get_contents($filePath);
        
        if ($fileContent === false) {
            return null;
        }

        $threatIndicators = [
            'exe' => ['executable', 'binary'],
            'dll' => ['library', 'binary'],
            'bat' => ['batch', 'script'],
            'vbs' => ['script', 'visual basic'],
            'js' => ['javascript', 'script'],
            'php' => ['php', 'script']
        ];

        $suspiciousPatterns = [
            'eval\s*\(',
            'base64_decode\s*\(',
            'system\s*\(',
            'exec\s*\(',
            'shell_exec\s*\(',
            'passthru\s*\('
        ];

        if (array_key_exists($fileExtension, $threatIndicators)) {
            return [
                'id' => uniqid('threat-'),
                'name' => basename($filePath),
                'type' => $threatIndicators[$fileExtension][0],
                'severity' => 'medium',
                'location' => $filePath,
                'description' => 'Potential ' . $threatIndicators[$fileExtension][1] . ' file detected',
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $fileContent)) {
                return [
                    'id' => uniqid('threat-'),
                    'name' => basename($filePath),
                    'type' => 'Suspicious Code',
                    'severity' => 'high',
                    'location' => $filePath,
                    'description' => 'Suspicious code pattern detected',
                    'timestamp' => date('Y-m-d H:i:s')
                ];
            }
        }

        return null;
    }

    protected function getStatusMessage($progress) {
        if ($progress < 30) {
            return 'Scanning system files...';
        } else if ($progress < 60) {
            return 'Analyzing memory...';
        } else if ($progress < 90) {
            return 'Checking registry...';
        } else {
            return 'Finalizing scan...';
        }
    }

    protected function sendToAll($msg) {
        foreach ($this->clients as $client) {
            $client->send($msg);
        }
    }
}

$server = IoServer::factory(
    new HttpServer(
        new WsServer(
            new ScanServer()
        )
    ),
    8080
);

$server->run();
?> 