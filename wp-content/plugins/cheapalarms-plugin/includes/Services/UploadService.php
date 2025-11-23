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

class UploadService
{
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
        $token    = $this->signToken([
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'iat'        => $issuedAt,
            'exp'        => $exp,
            'jti'        => wp_generate_uuid4(),
            'ip'         => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
        ], $secret);

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
            return new WP_Error('unauthorized', __('Missing token.', 'cheapalarms'), ['status' => 401]);
        }

        [$payloadB64, $sigB64] = explode('.', $token, 2);
        $expected = $this->base64UrlEncode(hash_hmac('sha256', $payloadB64, $secret, true));
        if (!hash_equals($expected, $sigB64)) {
            return new WP_Error('unauthorized', __('Invalid token signature.', 'cheapalarms'), ['status' => 401]);
        }

        $payloadJson = base64_decode(strtr($payloadB64, '-_', '+/'));
        $tokenData   = json_decode($payloadJson, true);
        if (!$tokenData || empty($tokenData['exp']) || time() > (int)$tokenData['exp']) {
            return new WP_Error('unauthorized', __('Token expired.', 'cheapalarms'), ['status' => 401]);
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (!empty($tokenData['ip']) && $tokenData['ip'] !== $ip) {
            return new WP_Error('unauthorized', __('IP mismatch.', 'cheapalarms'), ['status' => 401]);
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

        $attachmentId = media_handle_sideload($tmp, 0, 'Estimate ' . $tokenData['estimateId'] . ' upload');
        if (is_wp_error($attachmentId)) {
            return $attachmentId;
        }

        $url = wp_get_attachment_url($attachmentId);
        if (!$url) {
            return new WP_Error('server_error', __('Unable to retrieve uploaded file URL.', 'cheapalarms'), ['status' => 500]);
        }

        return [
            'ok'           => true,
            'url'          => $url,
            'attachmentId' => $attachmentId,
        ];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function signToken(array $payload, string $secret): string
    {
        $encodedPayload = $this->base64UrlEncode(wp_json_encode($payload));
        $signature      = $this->base64UrlEncode(hash_hmac('sha256', $encodedPayload, $secret, true));
        return $encodedPayload . '.' . $signature;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}

