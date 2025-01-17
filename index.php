<?php
/**
 * =============================================================================
 * LightspeedPHPServ: Secure, in-memory static file server using APCu for 
 * ultra-fast delivery under Apache + PHP, with enhanced security measures.
 *
 * REQUIREMENTS:
 *  - PHP 7.4 or higher.
 *  - APCu extension installed and enabled.
 *  - .htaccess or Apache config that rewrites all requests (including images, CSS, JS)
 *    to this file (Front Controller).
 *
 * EXAMPLE .htaccess (place in the same folder as this script):
 * -----------------------------------------------------------------------------
 *   <IfModule mod_rewrite.c>
 *     RewriteEngine On
 *     RewriteRule ^(.*)$ index.php [QSA,L]
 *   </IfModule>
 * -----------------------------------------------------------------------------
 * Ensure "AllowOverride All" is set in your Apache config for this directory.
 *
 * USAGE:
 *  1) Put this file (e.g., "index.php") in your web root or a suitable folder.
 *  2) Place all static files (HTML, CSS, JS, images, etc.) in a "public" subfolder.
 *  3) Adjust the $publicDir path below.
 *  4) Open your domain in the browser. All requests will be served from memory once cached.
 */

declare(strict_types=1);

namespace MyApp;

// ----------------------------------------------------------------------------
// Secure Configuration Hints:
//   - For production, you typically disable error display and log errors instead.
//   - Make sure you keep your OS, PHP version, APCu, and web server updated.
// ----------------------------------------------------------------------------
ini_set('display_errors', '0');  // Do NOT show errors publicly in production
error_reporting(E_ALL);          // Log all errors (but don't display them)

/**
 * Main class: LightspeedPHPServ
 */
class LightspeedPHPServ
{
    /**
     * Absolute path to the public directory containing static files.
     * @var string
     */
    private string $publicDirectory;

    /**
     * Cache key prefix to avoid naming collisions in APCu.
     * @var string
     */
    private string $cachePrefix;

    /**
     * The HTTP protocol version string, e.g. "HTTP/1.1".
     * @var string
     */
    private string $httpVersion;

    /**
     * The HTTP method, e.g. GET, HEAD, POST, etc.
     * @var string
     */
    private string $method;

    /**
     * The requested path extracted from the URL, normalized for security.
     * @var string
     */
    private string $requestedPath;

    /**
     * Allowed file extensions (whitelist). Deny everything else.
     * Adjust as needed for your application.
     * @var string[]
     */
    private array $allowedExtensions = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'css', 'js',
        'html', 'htm', 'json', 'pdf', 'txt', 'svg', 'ico'
    ];

    /**
     * Constructor.
     *
     * @param string $publicDirectory Absolute path to the "public" folder.
     * @param string $cachePrefix     String prefix for APCu cache keys.
     */
    public function __construct(string $publicDirectory, string $cachePrefix = 'lightspeed_')
    {
        $this->publicDirectory = rtrim($publicDirectory, '/\\');
        $this->cachePrefix     = $cachePrefix;

        // Basic server info
        $this->httpVersion = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
        $this->method      = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

        // Extract requested path from REQUEST_URI
        $requestUri        = $_SERVER['REQUEST_URI'] ?? '/';
        $parsedUrl         = parse_url($requestUri);
        $rawPath           = $parsedUrl['path'] ?? '/';
        $this->requestedPath = $this->normalizeRequestPath($rawPath);

        // Fallback if just "/" is requested
        if ($this->requestedPath === '/') {
            $this->requestedPath = '/index.html';
        }
    }

    /**
     * Main entry point: Handles the incoming request.
     *  1) Adds common security headers to every response.
     *  2) Validates the requested file is under $publicDirectory and has an allowed extension.
     *  3) Loads file from APCu or from disk.
     *  4) Sends the file with the appropriate headers.
     *
     * @return void
     */
    public function handleRequest(): void
    {
        // 1) Add security headers to every response (before sending anything else).
        $this->addSecurityHeaders();

        // Determine the real file system path
        $targetFilePath = $this->publicDirectory . $this->requestedPath;

        // Check if the file actually exists under $publicDirectory
        $realPublicDir  = realpath($this->publicDirectory);
        $realTargetFile = realpath($targetFilePath);

        if (!$realTargetFile || !$realPublicDir || strpos($realTargetFile, $realPublicDir) !== 0) {
            // File doesn't exist or it's outside of $publicDirectory
            $this->sendNotFound();
            return;
        }

        // 2) Enforce allowed file extensions
        $ext = strtolower(pathinfo($realTargetFile, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->allowedExtensions, true)) {
            $this->sendForbidden();
            return;
        }

        // 3) If APCu is unavailable, just send the file directly from disk
        if (!$this->isApcuEnabled()) {
            $this->sendFileDirect($realTargetFile);
            return;
        }

        // Attempt to fetch the file data from APCu
        $cacheKey = $this->cachePrefix . $realTargetFile;
        $cached   = \apcu_fetch($cacheKey);

        if (!$cached) {
            // Not in cache -> read from disk
            if (!is_file($realTargetFile)) {
                $this->sendNotFound();
                return;
            }

            $content = @file_get_contents($realTargetFile);
            if ($content === false) {
                $this->sendNotFound();
                return;
            }

            $mimeType          = $this->detectMimeType($realTargetFile);
            $lastModifiedTime  = filemtime($realTargetFile) ?: time();
            $lastModifiedHttp  = gmdate('D, d M Y H:i:s', $lastModifiedTime) . ' GMT';
            $contentLength     = strlen($content);

            $cached = [
                'content'      => $content,
                'mimeType'     => $mimeType,
                'length'       => $contentLength,
                'lastModified' => $lastModifiedHttp,
            ];

            \apcu_store($cacheKey, $cached);
        }

        // 4) Now send the file from memory
        $this->sendFromCache($cached);
    }

    /**
     * Sends the recommended security headers on every response before status lines.
     * Adjust or remove headers not suitable for your environment (e.g. HSTS if not using HTTPS).
     */
    private function addSecurityHeaders(): void
    {
        // Helps prevent MIME-sniffing
        header('X-Content-Type-Options: nosniff');

        // Protects against clickjacking
        header('X-Frame-Options: SAMEORIGIN');

        // Basic Content Security Policy (CSP); adjust as needed
        header("Content-Security-Policy: default-src 'self'");

        // Enforce strict transport security (only if you're using HTTPS)
        // Adjust max-age as needed; remove if not using HTTPS
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    /**
     * Sends a 404 Not Found response.
     * Logs the error for analysis.
     *
     * @return void
     */
    private function sendNotFound(): void
    {
        error_log('LightspeedPHPServ: 404 Not Found - ' . $this->requestedPath);
        header($this->httpVersion . ' 404 Not Found');
        header('Content-Type: text/plain; charset=utf-8');
        echo '404 Not Found';
    }

    /**
     * Sends a 403 Forbidden response (used for disallowed file types).
     * Logs the error for analysis.
     *
     * @return void
     */
    private function sendForbidden(): void
    {
        error_log('LightspeedPHPServ: 403 Forbidden - ' . $this->requestedPath);
        header($this->httpVersion . ' 403 Forbidden');
        header('Content-Type: text/plain; charset=utf-8');
        echo '403 Forbidden';
    }

    /**
     * Sends a 405 Method Not Allowed response for methods other than GET/HEAD.
     *
     * @return void
     */
    private function sendMethodNotAllowed(): void
    {
        error_log('LightspeedPHPServ: 405 Method Not Allowed - ' . $this->method);
        header($this->httpVersion . ' 405 Method Not Allowed');
        header('Allow: GET, HEAD');
        header('Content-Type: text/plain; charset=utf-8');
        echo '405 Method Not Allowed';
    }

    /**
     * Sends file data (from APCu cache) to the client, handling GET and HEAD.
     *
     * @param array $cached Associative array with keys: content, mimeType, length, lastModified.
     *
     * @return void
     */
    private function sendFromCache(array $cached): void
    {
        switch ($this->method) {
            case 'GET':
                $this->sendStandardHeaders(200, $cached['mimeType'], $cached['length'], $cached['lastModified']);
                echo $cached['content'];
                break;

            case 'HEAD':
                $this->sendStandardHeaders(200, $cached['mimeType'], $cached['length'], $cached['lastModified']);
                break;

            default:
                $this->sendMethodNotAllowed();
                break;
        }
    }

    /**
     * Directly read and send file contents from the disk (fallback if APCu is unavailable).
     *
     * @param string $filePath Absolute path to the file on disk.
     *
     * @return void
     */
    private function sendFileDirect(string $filePath): void
    {
        if (!is_file($filePath)) {
            $this->sendNotFound();
            return;
        }

        $content = @file_get_contents($filePath);
        if ($content === false) {
            $this->sendNotFound();
            return;
        }

        $mimeType         = $this->detectMimeType($filePath);
        $lastModifiedTime = filemtime($filePath) ?: time();
        $lastModifiedHttp = gmdate('D, d M Y H:i:s', $lastModifiedTime) . ' GMT';
        $contentLength    = strlen($content);

        switch ($this->method) {
            case 'GET':
                $this->sendStandardHeaders(200, $mimeType, $contentLength, $lastModifiedHttp);
                echo $content;
                break;

            case 'HEAD':
                $this->sendStandardHeaders(200, $mimeType, $contentLength, $lastModifiedHttp);
                break;

            default:
                $this->sendMethodNotAllowed();
                break;
        }
    }

    /**
     * Sends common headers (HTTP status, Content-Type, Content-Length, Last-Modified).
     *
     * @param int    $statusCode       HTTP status code (e.g. 200, 404, etc.).
     * @param string $mimeType         Detected MIME type of the file.
     * @param int    $contentLength    Length of the content to be sent.
     * @param string $lastModifiedHttp Formatted last-modified date.
     *
     * @return void
     */
    private function sendStandardHeaders(
        int $statusCode,
        string $mimeType,
        int $contentLength,
        string $lastModifiedHttp
    ): void {
        $statusText = $this->getStatusText($statusCode);
        header("{$this->httpVersion} {$statusCode} {$statusText}");
        header("Content-Type: {$mimeType}");
        header("Content-Length: {$contentLength}");
        header("Last-Modified: {$lastModifiedHttp}");
    }

    /**
     * Returns a standard HTTP status text for common codes.
     *
     * @param int $statusCode
     * @return string
     */
    private function getStatusText(int $statusCode): string
    {
        return match ($statusCode) {
            200 => 'OK',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            default => 'OK', // fallback
        };
    }

    /**
     * Checks if APCu is available and enabled.
     * Also does some basic configuration checks (optional).
     *
     * @return bool
     */
    private function isApcuEnabled(): bool
    {
        if (!function_exists('apcu_enabled') || !\apcu_enabled()) {
            return false;
        }
        // Optional: Check memory limit or other APCu settings
        // $shmSize = ini_get('apc.shm_size');
        // if ($shmSize < some_threshold) { /* log or handle it */ }
        return true;
    }

    /**
     * Determines the MIME type of a file using mime_content_type if available,
     * otherwise falls back to a simple extension-based map.
     *
     * @param string $filePath Absolute path to the file.
     * @return string The detected or guessed MIME type.
     */
    private function detectMimeType(string $filePath): string
    {
        if (function_exists('mime_content_type')) {
            $maybeMime = @mime_content_type($filePath);
            if ($maybeMime !== false && $maybeMime !== '') {
                return $maybeMime;
            }
        }
        return $this->guessMimeTypeByExtension($filePath);
    }

    /**
     * Simple fallback MIME type detection based on file extension.
     *
     * @param string $filePath
     * @return string
     */
    private function guessMimeTypeByExtension(string $filePath): string
    {
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $map = [
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png'  => 'image/png',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
            'css'  => 'text/css',
            'js'   => 'application/javascript',
            'html' => 'text/html',
            'htm'  => 'text/html',
            'json' => 'application/json',
            'pdf'  => 'application/pdf',
            'txt'  => 'text/plain',
            'svg'  => 'image/svg+xml',
            'ico'  => 'image/x-icon',
        ];
        return $map[$ext] ?? 'application/octet-stream';
    }

    /**
     * Normalizes the request path by removing backslashes, double slashes,
     * and potential ".." sequences to minimize directory traversal attacks.
     * Also consider re-checking URL-encoded attempts, if needed.
     *
     * @param string $rawPath Raw path from parse_url().
     * @return string The normalized path, always starting with "/".
     */
    private function normalizeRequestPath(string $rawPath): string
    {
        // Decode in case of URL-encoded traversal like %2e%2e
        $decoded = urldecode($rawPath);

        // Replace backslashes
        $decoded = str_replace('\\', '/', $decoded);

        // Collapse multiple slashes
        $decoded = preg_replace('#/+#', '/', $decoded);

        // Remove ".." sequences
        $decoded = preg_replace('#\.\.+#', '', $decoded);

        // Ensure it starts with "/"
        if (!str_starts_with($decoded, '/')) {
            $decoded = '/' . $decoded;
        }

        return $decoded;
    }
}

// =============================================================================
// Example usage (Front Controller in index.php):
// =============================================================================

// If you have Composer autoload, you can load it here:
// require_once __DIR__ . '/vendor/autoload.php';

// Use the namespace and class
use MyApp\LightspeedPHPServ;

// Adjust the path to your "public" directory as needed:
$publicDir = __DIR__ . '/public';

// Instantiate and handle the request
$server = new LightspeedPHPServ($publicDir);
$server->handleRequest();
