<?php
header('Content-Type: application/json');

// Function to scan a directory recursively
function scanDirectory($path, $scanType) {
    $results = [
        'files' => [],
        'threats' => []
    ];
    
    if (!is_dir($path)) {
        return $results;
    }
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $filePath = $file->getPathname();
            $fileInfo = [
                'path' => $filePath,
                'size' => $file->getSize(),
                'modified' => date('Y-m-d H:i:s', $file->getMTime())
            ];
            
            // Check for potential threats based on file type and content
            $threat = checkForThreats($filePath, $scanType);
            if ($threat) {
                $results['threats'][] = $threat;
            }
            
            $results['files'][] = $fileInfo;
        }
    }
    
    return $results;
}

// Function to check for potential threats
function checkForThreats($filePath, $scanType) {
    $fileExtension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    $fileContent = file_get_contents($filePath);
    
    // Common threat indicators
    $threatIndicators = [
        'exe' => ['executable', 'binary'],
        'dll' => ['library', 'binary'],
        'bat' => ['batch', 'script'],
        'vbs' => ['script', 'visual basic'],
        'js' => ['javascript', 'script'],
        'php' => ['php', 'script']
    ];
    
    // Suspicious patterns
    $suspiciousPatterns = [
        'eval\s*\(',
        'base64_decode\s*\(',
        'system\s*\(',
        'exec\s*\(',
        'shell_exec\s*\(',
        'passthru\s*\('
    ];
    
    // Check file extension
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
    
    // Check for suspicious patterns in file content
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

// Handle the scan request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $scanType = $_POST['scanType'] ?? 'quick';
    $scanTarget = $_POST['scanTarget'] ?? 'system';
    
    // Define scan paths based on scan type
    $scanPaths = [
        'quick' => ['C:\\Windows\\System32'],
        'full' => ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)'],
        'custom' => [$scanTarget]
    ];
    
    $results = [
        'scanType' => $scanType,
        'scanTarget' => $scanTarget,
        'filesScanned' => 0,
        'threats' => [],
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    // Perform the scan
    foreach ($scanPaths[$scanType] as $path) {
        $scanResult = scanDirectory($path, $scanType);
        $results['filesScanned'] += count($scanResult['files']);
        $results['threats'] = array_merge($results['threats'], $scanResult['threats']);
    }
    
    // Calculate scan duration
    $startTime = microtime(true);
    $results['scanDuration'] = round(microtime(true) - $startTime, 2);
    
    echo json_encode($results);
} else {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
}
?> 