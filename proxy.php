<?php
/**
 * PHP Proxy for What Body Game
 * This proxy helps bypass X-Frame-Options restrictions
 * File: proxy.php
 */

// Enable error reporting for debugging (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// CORS headers to allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Security: Only allow specific domains to prevent abuse
$allowedDomains = [
    'itch.io',
    'bun-tired.itch.io',
    'v6p9d9t4.ssl.hwcdn.net'  // itch.io CDN
];

// Get the target URL from query parameter
$targetUrl = isset($_GET['url']) ? $_GET['url'] : '';

if (empty($targetUrl)) {
    http_response_code(400);
    die('Error: No URL specified. Usage: proxy.php?url=TARGET_URL');
}

// Validate URL format
if (!filter_var($targetUrl, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    die('Error: Invalid URL format');
}

// Parse URL to check domain
$parsedUrl = parse_url($targetUrl);
$domain = $parsedUrl['host'];

// Check if domain is allowed
$domainAllowed = false;
foreach ($allowedDomains as $allowedDomain) {
    if (strpos($domain, $allowedDomain) !== false) {
        $domainAllowed = true;
        break;
    }
}

if (!$domainAllowed) {
    http_response_code(403);
    die('Error: Domain not allowed');
}

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt_array($ch, [
    CURLOPT_URL => $targetUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    CURLOPT_HEADERFUNCTION => function($curl, $header) {
        $len = strlen($header);
        $header = explode(':', $header, 2);
        
        if (count($header) < 2) {
            return $len;
        }
        
        $name = strtolower(trim($header[0]));
        $value = trim($header[1]);
        
        // Skip problematic headers that prevent embedding
        if (in_array($name, ['x-frame-options', 'content-security-policy', 'x-content-type-options'])) {
            return $len;
        }
        
        // Forward other headers
        if (!in_array($name, ['transfer-encoding', 'content-encoding'])) {
            header($name . ': ' . $value);
        }
        
        return $len;
    }
]);

// Execute cURL request
$response = curl_exec($ch);

// Check for cURL errors
if (curl_error($ch)) {
    $error = curl_error($ch);
    curl_close($ch);
    http_response_code(500);
    die('cURL Error: ' . $error);
}

// Get HTTP status code
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Set the HTTP response code
http_response_code($httpCode);

// Process the response content
if ($response !== false) {
    // Modify the HTML content to fix relative URLs and remove frame-busting scripts
    if (strpos($targetUrl, 'itch.io') !== false) {
        $response = processItchIoContent($response, $targetUrl);
    }
    
    echo $response;
} else {
    http_response_code(500);
    die('Error: Failed to fetch content');
}

/**
 * Process itch.io content to make it embeddable
 */
function processItchIoContent($content, $baseUrl) {
    $parsedUrl = parse_url($baseUrl);
    $baseHost = $parsedUrl['scheme'] . '://' . $parsedUrl['host'];
    
    // Remove or modify frame-busting scripts
    $content = preg_replace('/if\s*\(\s*top\s*!=\s*self\s*\).*?}/s', '', $content);
    $content = preg_replace('/if\s*\(\s*parent\s*!=\s*window\s*\).*?}/s', '', $content);
    $content = preg_replace('/top\.location\s*=\s*self\.location/i', '', $content);
    $content = preg_replace('/parent\.location\s*=\s*self\.location/i', '', $content);
    
    // Fix relative URLs
    $content = preg_replace('/src=["\']\/(.*?)["\']/i', 'src="' . $baseHost . '/$1"', $content);
    $content = preg_replace('/href=["\']\/(.*?)["\']/i', 'href="' . $baseHost . '/$1"', $content);
    $content = preg_replace('/url\(["\']\/(.*?)["\']\)/i', 'url("' . $baseHost . '/$1")', $content);
    
    // Add custom CSS to ensure the content fits properly in iframe
    $customCSS = '<style>
        body { margin: 0; padding: 0; overflow: hidden; }
        .game_frame, #game_frame { width: 100% !important; height: 100vh !important; border: none !important; }
        .header, .footer, .sidebar { display: none !important; }
    </style>';
    
    // Insert custom CSS before closing head tag
    if (strpos($content, '</head>') !== false) {
        $content = str_replace('</head>', $customCSS . '</head>', $content);
    } else {
        $content = $customCSS . $content;
    }
    
    return $content;
}

/**
 * Simple cache mechanism (optional)
 */
function getCachedContent($url, $cacheTime = 300) { // 5 minutes cache
    $cacheDir = __DIR__ . '/cache/';
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }
    
    $cacheFile = $cacheDir . md5($url) . '.cache';
    
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTime) {
        return file_get_contents($cacheFile);
    }
    
    return false;
}

function setCachedContent($url, $content) {
    $cacheDir = __DIR__ . '/cache/';
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }
    
    $cacheFile = $cacheDir . md5($url) . '.cache';
    file_put_contents($cacheFile, $content);
}

/**
 * Security function to prevent abuse
 */
function rateLimitCheck() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $currentTime = time();
    $timeWindow = 60; // 1 minute
    $maxRequests = 10; // Max 10 requests per minute per IP
    
    $logFile = __DIR__ . '/rate_limit.log';
    $requests = [];
    
    if (file_exists($logFile)) {
        $requests = json_decode(file_get_contents($logFile), true) ?: [];
    }
    
    // Clean old entries
    $requests = array_filter($requests, function($timestamp) use ($currentTime, $timeWindow) {
        return ($currentTime - $timestamp) < $timeWindow;
    });
    
    // Count requests from this IP
    $ipRequests = array_filter($requests, function($timestamp, $requestIp) use ($ip) {
        return $requestIp === $ip;
    }, ARRAY_FILTER_USE_BOTH);
    
    if (count($ipRequests) >= $maxRequests) {
        http_response_code(429);
        die('Rate limit exceeded. Please try again later.');
    }
    
    // Add current request
    $requests[$ip . '_' . uniqid()] = $currentTime;
    
    file_put_contents($logFile, json_encode($requests));
}

// Uncomment to enable rate limiting
// rateLimitCheck();

?>
