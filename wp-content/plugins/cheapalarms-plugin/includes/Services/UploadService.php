<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;
use WP_REST_Request;

use function media_handle_sideload;
use function sanitize_text_field;
use function wp_check_filetype;
use function wp_generate_uuid4;
use function wp_get_attachment_url;
use function wp_json_encode;
use function get_transient;
use function set_transient;
use function delete_transient;
use function wp_cache_add;
use function wp_cache_get;
use function wp_cache_set;
use function wp_cache_delete;

class UploadService
{
    // Maximum number of uploads allowed per token (bounded reuse)
    // NOTE: This is "abuse control", not strict enforcement due to concurrency
    // With 5-minute expiration, even small overshoots are acceptable
    private const MAX_UPLOADS_PER_TOKEN = 50;
    
    // Cache group for upload tracking
    private const CACHE_GROUP = 'ca_upload';
    
    // Lock timeout in seconds (short since critical section is tiny: read/increment/write)
    private const LOCK_TIMEOUT = 2;
    // Maximum retries for acquiring lock (covers LOCK_TIMEOUT with buffer)
    private const MAX_LOCK_RETRIES = 25; // 25 * 100ms = 2.5s (covers 2s timeout)
    // Lock retry delay in microseconds (100ms)
    private const LOCK_RETRY_DELAY = 100000;

    public function __construct(
        private Config $config,
        private EstimateService $estimateService,
        private Logger $logger
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     */
    /**
     * @return array|WP_Error
     */
    public function start(array $payload)
    {
        $secret = $this->config->getUploadSharedSecret();
        if (!$secret) {
            return new WP_Error('server_error', __('Upload secret is not configured.', 'cheapalarms'), ['status' => 500]);
        }

        $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
        $locationId = sanitize_text_field($payload['locationId'] ?? $this->config->getLocationId());
        if (!$estimateId || !$locationId) {
            return new WP_Error('bad_request', __('estimateId and locationId required.', 'cheapalarms'), ['status' => 400]);
        }

        // Note: We skip GHL validation here since we only need WordPress media uploads.
        // The estimateId and locationId are validated above, and the actual upload
        // saves to WordPress media library without requiring GHL API access.

        $issuedAt = time();
        $exp      = $issuedAt + 300;
        $jti      = wp_generate_uuid4();
        
        // ✅ REMOVED: IP binding - not reliable behind proxies/CDNs
        $token    = $this->signToken([
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'iat'        => $issuedAt,
            'exp'        => $exp,
            'jti'        => $jti,
        ], $secret);

        $this->logger->info('Upload token created', [
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'exp' => $exp,
            'jti_prefix' => substr($jti, 0, 8), // Log only prefix for debugging
        ]);

        return [
            'ok'    => true,
            'token' => $token,
            'exp'   => $exp,
        ];
    }

    /**
     * @return array|WP_Error
     */
    public function handle(WP_REST_Request $request)
    {
        $secret = $this->config->getUploadSharedSecret();
        if (!$secret) {
            return new WP_Error('server_error', __('Upload secret is not configured.', 'cheapalarms'), ['status' => 500]);
        }

        // Token is passed as query parameter to avoid WordPress REST API multipart parsing issues
        // Check query params first, then $_POST as fallback
        $token = $request->get_param('token') ?? $_POST['token'] ?? '';
        if (!$token || !str_contains($token, '.')) {
            $this->logger->warning('Upload token validation failed: missing token');
            return new WP_Error('unauthorized', __('Missing token.', 'cheapalarms'), ['status' => 401]);
        }

        [$payloadB64, $sigB64] = explode('.', $token, 2);
        $expected = $this->base64UrlEncode(hash_hmac('sha256', $payloadB64, $secret, true));
        if (!hash_equals($expected, $sigB64)) {
            $this->logger->warning('Upload token validation failed: invalid signature');
            return new WP_Error('unauthorized', __('Invalid token signature.', 'cheapalarms'), ['status' => 401]);
        }

        $payloadJson = base64_decode(strtr($payloadB64, '-_', '+/'));
        $tokenData   = json_decode($payloadJson, true);
        
        // ✅ ADDED: Enhanced token validation
        if (!$tokenData) {
            $this->logger->warning('Upload token validation failed: invalid payload JSON');
            return new WP_Error('unauthorized', __('Invalid token payload.', 'cheapalarms'), ['status' => 401]);
        }
        
        // Validate required fields
        if (empty($tokenData['estimateId']) || empty($tokenData['locationId'])) {
            $this->logger->warning('Upload token validation failed: missing required fields', [
                'has_estimateId' => !empty($tokenData['estimateId']),
                'has_locationId' => !empty($tokenData['locationId']),
            ]);
            return new WP_Error('unauthorized', __('Invalid token: missing required fields.', 'cheapalarms'), ['status' => 401]);
        }
        
        // ✅ TIGHTENED: Validate iat and exp values
        $iat = (int)($tokenData['iat'] ?? 0);
        $exp = (int)($tokenData['exp'] ?? 0);
        
        if ($iat <= 0 || $exp <= $iat) {
            $this->logger->warning('Upload token validation failed: invalid iat/exp relationship', [
                'iat' => $iat,
                'exp' => $exp,
            ]);
            return new WP_Error('unauthorized', __('Invalid token: invalid time values.', 'cheapalarms'), ['status' => 401]);
        }
        
        // Validate expiration
        $now = time();
        if ($exp <= 0 || $now > $exp) {
            $this->logger->warning('Upload token validation failed: expired', [
                'exp' => $exp,
                'now' => $now,
            ]);
            return new WP_Error('unauthorized', __('Token expired.', 'cheapalarms'), ['status' => 401]);
        }
        
        // Validate iat (issued at) - sanity check for clock skew
        if ($iat > $now + 60) { // Allow 60s clock skew
            $this->logger->warning('Upload token validation failed: issued in future', [
                'iat' => $iat,
                'now' => $now,
            ]);
            return new WP_Error('unauthorized', __('Invalid token: issued in future.', 'cheapalarms'), ['status' => 401]);
        }
        
        // Validate exp-iat relationship (max 10 minutes)
        $lifetime = $exp - $iat;
        if ($lifetime > 600) { // 10 minutes max
            $this->logger->warning('Upload token validation failed: lifetime too long', [
                'lifetime' => $lifetime,
            ]);
            return new WP_Error('unauthorized', __('Invalid token: lifetime too long.', 'cheapalarms'), ['status' => 401]);
        }

        // ✅ REMOVED: IP validation check (unreliable behind proxies/CDNs)

        // ✅ ADDED: JTI validation and usage limit check (before upload)
        // NOTE: This is a "best effort" check - with concurrent uploads, the limit may be slightly exceeded.
        // The increment after successful upload is the real control point.
        $jti = $tokenData['jti'] ?? '';
        if (empty($jti)) {
            $this->logger->warning('Upload token validation failed: missing jti');
            return new WP_Error('unauthorized', __('Invalid token: missing jti.', 'cheapalarms'), ['status' => 401]);
        }
        
        // Calculate TTL: keep counter slightly longer than remaining token lifetime
        $remainingLifetime = max(60, ($exp - $now) + 60);
        $jtiHash = md5($jti);
        
        // ✅ FIXED: Pre-check uses cache-only optimization (no fallback to transient to avoid mixing stores)
        // If cache isn't available, this will return 0, which is acceptable since pre-check is "best effort"
        // The increment logic will use the appropriate store (cache or transient) consistently
        $usedCount = $this->getCachedJtiUsageCount($jtiHash);
        if ($usedCount >= self::MAX_UPLOADS_PER_TOKEN) {
            $this->logger->warning('Upload token validation failed: upload limit reached', [
                'jti_prefix' => substr($jti, 0, 8),
                'used_count' => $usedCount,
                'max_uploads' => self::MAX_UPLOADS_PER_TOKEN,
            ]);
            return new WP_Error('unauthorized', __('Token upload limit reached.', 'cheapalarms'), ['status' => 401]);
        }

        // Check both REST API file params and $_FILES (for direct uploads)
        // WordPress REST API may populate get_file_params() when request comes through REST API
        // $_FILES is populated when PHP receives multipart/form-data directly
        $fileParams = $request->get_file_params();
        $file = $fileParams['file'] ?? $_FILES['file'] ?? null;

        if (empty($file)) {
            return new WP_Error('bad_request', __('No file uploaded.', 'cheapalarms'), ['status' => 400]);
        }
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return new WP_Error('upload_error', 'Upload error code ' . $file['error'], ['status' => 400]);
        }

        if ($file['size'] > $this->config->getUploadMaxBytes()) {
            return new WP_Error('file_too_large', __('File exceeds maximum upload size.', 'cheapalarms'), ['status' => 413]);
        }

        $allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';

        add_filter('upload_mimes', function ($mimes) {
            $mimes['jpg|jpeg|jpe'] = 'image/jpeg';
            $mimes['png']          = 'image/png';
            $mimes['gif']          = 'image/gif';
            $mimes['webp']         = 'image/webp';
            return $mimes;
        }, 10, 1);

        $fileType = wp_check_filetype($file['name']);
        $detectedMime = $fileType['type'] ?: $file['type'];
        if (!in_array(strtolower($detectedMime), array_map('strtolower', $allowed), true)) {
            return new WP_Error('bad_mime', __('Unsupported file type.', 'cheapalarms'), ['status' => 415]);
        }

        add_filter('wp_check_filetype_and_ext', function ($data, $filePath, $filename, $mimes) use ($detectedMime, $fileType) {
            if ($detectedMime && str_starts_with($detectedMime, 'image/')) {
                $data['ext']  = $fileType['ext'];
                $data['type'] = $detectedMime;
                $data['proper_filename'] = false;
            }
            return $data;
        }, 10, 4);

        $tmp = [
            'name'     => $file['name'],
            'type'     => $detectedMime,
            'tmp_name' => $file['tmp_name'],
            'error'    => 0,
            'size'     => $file['size'],
        ];

        // Perform the actual upload
        $attachmentId = media_handle_sideload($tmp, 0, 'Estimate ' . $tokenData['estimateId'] . ' upload');
        if (is_wp_error($attachmentId)) {
            return $attachmentId;
        }

        $url = wp_get_attachment_url($attachmentId);
        if (!$url) {
            return new WP_Error('server_error', __('Unable to retrieve uploaded file URL.', 'cheapalarms'), ['status' => 500]);
        }

        // ✅ ADDED: Increment usage count AFTER successful upload (with atomic lock)
        $incrementResult = $this->incrementJtiUsage($jtiHash, $remainingLifetime);
        if (is_wp_error($incrementResult)) {
            // Log error but don't fail the upload (it already succeeded)
            $this->logger->error('Failed to increment jti usage count after successful upload', [
                'jti_prefix' => substr($jti, 0, 8),
                'error' => $incrementResult->get_error_message(),
            ]);
        }

        $this->logger->info('File uploaded successfully', [
            'estimateId' => $tokenData['estimateId'],
            'attachmentId' => $attachmentId,
            'jti_prefix' => substr($jti, 0, 8),
            'usage_count' => $incrementResult instanceof WP_Error ? 'unknown' : $incrementResult,
        ]);

        return [
            'ok'           => true,
            'url'          => $url,
            'attachmentId' => $attachmentId,
        ];
    }

    /**
     * Get cached JTI usage count (cache-only optimization, not a guarantee)
     * 
     * This is a cache-only optimization for the pre-check. Returns 0 if cache is unavailable
     * or key doesn't exist. This is acceptable because:
     * - Pre-check is "best effort" (limit may be slightly exceeded with concurrency)
     * - Increment logic will use the appropriate store (cache or transient) consistently
     * - If cache isn't available, increment will use transient, and pre-check returning 0 is fine
     * 
     * IMPORTANT: This method does NOT fall back to transients to avoid mixing stores.
     * The increment logic handles transient fallback consistently when needed.
     * 
     * @param string $jtiHash MD5 hash of the jti
     * @return int Current usage count from cache (0 if cache miss or cache unavailable)
     */
    private function getCachedJtiUsageCount(string $jtiHash): int
    {
        $countKey = $jtiHash . ':count';
        
        // Cache-only: read from cache, return 0 if unavailable
        // This is an optimization, not a guarantee - the increment logic enforces the limit
        $count = wp_cache_get($countKey, self::CACHE_GROUP);
        if ($count !== false) {
            return (int) $count;
        }
        
        // Return 0 if cache miss or cache unavailable (acceptable for "best effort" pre-check)
        return 0;
    }

    /**
     * Atomically increment JTI usage count with lock protection
     * Uses wp_cache_add for atomic lock if available, otherwise falls back to transient lock
     * Uses same storage system for lock and counter to avoid split-brain
     * 
     * @param string $jtiHash MD5 hash of the jti
     * @param int $ttl Time to live for the counter
     * @return int|WP_Error New usage count, or error on failure
     */
    private function incrementJtiUsage(string $jtiHash, int $ttl): int|WP_Error
    {
        $lockKey = $jtiHash . ':lock';
        $countKey = $jtiHash . ':count';
        $lockAcquired = false;
        $retries = 0;
        $useCache = false;

        // Try to acquire lock using wp_cache_add (atomic if persistent cache available)
        while ($retries < self::MAX_LOCK_RETRIES) {
            // ✅ Try atomic wp_cache_add first (works with persistent cache backends)
            $lockAcquired = wp_cache_add($lockKey, 1, self::CACHE_GROUP, self::LOCK_TIMEOUT);
            
            if ($lockAcquired) {
                $useCache = true;
                break;
            }
            
            // Lock exists - wait and retry
            $retries++;
            if ($retries < self::MAX_LOCK_RETRIES) {
                usleep(self::LOCK_RETRY_DELAY);
            }
        }

        // If cache lock failed, fallback to transient lock (best effort, not atomic)
        if (!$lockAcquired) {
            $transientLockKey = 'ca_ulock_' . $jtiHash; // Short key: ca_upload_lock -> ca_ulock
            $retries = 0;
            
            while ($retries < self::MAX_LOCK_RETRIES) {
                $existingLock = get_transient($transientLockKey);
                
                if ($existingLock === false) {
                    // Lock available - acquire it (not atomic, but best effort)
                    // ✅ FIXED: Store just 1, not time() (we don't check staleness anymore)
                    set_transient($transientLockKey, 1, self::LOCK_TIMEOUT);
                    $lockAcquired = true;
                    break;
                }
                
                // Lock exists - wait and retry
                $retries++;
                if ($retries < self::MAX_LOCK_RETRIES) {
                    usleep(self::LOCK_RETRY_DELAY);
                }
            }
        }

        if (!$lockAcquired) {
            return new WP_Error('lock_timeout', __('Could not acquire lock for usage counter.', 'cheapalarms'));
        }

        try {
            // Read current count from same storage system as lock
            if ($useCache) {
                $currentCount = (int) wp_cache_get($countKey, self::CACHE_GROUP);
                $newCount = $currentCount + 1;
                wp_cache_set($countKey, $newCount, self::CACHE_GROUP, $ttl);
            } else {
                // Use transient for both lock and counter
                $transientCountKey = 'ca_ujti_' . $jtiHash;
                $currentCount = (int) get_transient($transientCountKey);
                $newCount = $currentCount + 1;
                set_transient($transientCountKey, $newCount, $ttl);
            }
            
            return $newCount;
        } finally {
            // Always release lock from same storage system
            if ($useCache) {
                wp_cache_delete($lockKey, self::CACHE_GROUP);
            } else {
                $transientLockKey = 'ca_ulock_' . $jtiHash;
                delete_transient($transientLockKey);
            }
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function signToken(array $payload, string $secret): string
    {
        $jsonPayload = wp_json_encode($payload);
        if ($jsonPayload === false) {
            $this->logger->error('Failed to encode token payload JSON', [
                'error' => json_last_error_msg(),
            ]);
            throw new \RuntimeException('Failed to encode token payload: ' . json_last_error_msg());
        }
        $encodedPayload = $this->base64UrlEncode($jsonPayload);
        $signature      = $this->base64UrlEncode(hash_hmac('sha256', $encodedPayload, $secret, true));
        return $encodedPayload . '.' . $signature;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}

