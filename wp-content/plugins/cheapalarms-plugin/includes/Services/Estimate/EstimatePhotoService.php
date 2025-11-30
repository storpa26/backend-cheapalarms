<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Services\EstimateService;
use WP_Error;

use function esc_url_raw;
use function get_option;
use function sanitize_text_field;
use function site_url;
use function update_option;
use function wp_json_encode;

/**
 * Handles photo-related operations for estimates.
 */
class EstimatePhotoService
{
    public function __construct(
        private Config $config,
        private EstimateService $estimateService,
        private \CheapAlarms\Plugin\Services\Logger $logger
    ) {
    }

    /**
     * Store photo mapping metadata for an estimate.
     *
     * @param array<string, mixed> $data
     * @return array|WP_Error
     */
    public function storePhotoMapping(array $data)
    {
        $estimateId = sanitize_text_field($data['estimateId'] ?? '');
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }
        if (!is_array($data['uploads'] ?? null)) {
            return new WP_Error('bad_request', __('uploads[] required', 'cheapalarms'), ['status' => 400]);
        }

        update_option('ca_estimate_uploads_' . $estimateId, wp_json_encode($data), false);

        return ['ok' => true];
    }

    /**
     * Apply stored photos to estimate items.
     *
     * @param array<string, mixed> $payload
     * @return array|WP_Error
     */
    public function applyPhotos(array $payload)
    {
        $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
        $locationId = sanitize_text_field($payload['locationId'] ?? $this->config->getLocationId());
        if (!$estimateId || !$locationId) {
            return new WP_Error('bad_request', __('estimateId and locationId required.', 'cheapalarms'), ['status' => 400]);
        }

        $raw = get_option('ca_estimate_uploads_' . $estimateId, '');
        if (!$raw) {
            return new WP_Error('not_found', __('No stored uploads for this estimate.', 'cheapalarms'), ['status' => 404]);
        }
        $map = json_decode($raw, true);
        if (!is_array($map)) {
            return new WP_Error('server_error', __('Invalid stored uploads JSON', 'cheapalarms'), ['status' => 500]);
        }

        // Use reflection or make method public temporarily to access private method
        // For now, we'll need to make mergePhotosIntoItems accessible
        $record = $this->estimateService->getEstimate(['estimateId' => $estimateId, 'locationId' => $locationId, 'raw' => 1]);
        if (is_wp_error($record)) {
            return $record;
        }

        $updated = $this->mergePhotosIntoItems($record, $map);

        $updatePayload = [
            'estimateId'        => $estimateId,
            'altId'             => $locationId,
            'altType'           => 'location',
            'name'              => $updated['name'],
            'title'             => $updated['title'],
            'businessDetails'   => $updated['businessDetails'],
            'currency'          => $updated['currency'],
            'discount'          => $updated['discount'],
            'contactDetails'    => $updated['contactDetails'],
            'issueDate'         => $updated['issueDate'],
            'expiryDate'        => $updated['expiryDate'],
            'frequencySettings' => $updated['frequencySettings'],
            'liveMode'          => $updated['liveMode'],
            'items'             => $updated['items'],
            'termsNotes'        => '<p>Photos received. We\'ll finalize pricing shortly.</p>',
        ];

        return $this->estimateService->updateEstimate($updatePayload);
    }

    /**
     * Build photo upload banner HTML.
     */
    public function buildPhotoBanner(string $estimateId): string
    {
        $link = esc_url_raw(site_url('/upload?estimateId=' . rawurlencode($estimateId)));

        return '<p><strong>Upload photos for this estimate:</strong> '
            . '<a href="' . $link . '" target="_blank" rel="noopener">' . $link . '</a></p>';
    }

    /**
     * Ensure photo link is in terms notes.
     */
    public function ensurePhotoLinkInTerms(string $terms, string $estimateId): string
    {
        $link = '/upload?estimateId=';
        if (strpos($terms, $link) !== false) {
            return $terms;
        }

        return $this->buildPhotoBanner($estimateId) . "\n" . $terms;
    }

    /**
     * Merge photos into estimate items.
     *
     * @param array<string, mixed> $record
     * @param array<string, mixed> $map
     * @return array<string, mixed>
     */
    private function mergePhotosIntoItems(array $record, array $map): array
    {
        $items = $record['items'] ?? [];
        if (!is_array($items)) {
            $items = [];
        }

        $uploadsByKey = [];
        foreach ($map['uploads'] as $upload) {
            if (!empty($upload['itemKey'])) {
                $uploadsByKey[(string)$upload['itemKey']] = $upload;
            }
            if (!empty($upload['itemName'])) {
                $exact      = trim($upload['itemName']);
                $normalized = strtolower($exact);
                $uploadsByKey[$exact] = $upload;
                $uploadsByKey[$normalized] = $upload;
                $normalizedNoSpaces = preg_replace('/\s+/', ' ', $normalized);
                if ($normalizedNoSpaces !== $normalized) {
                    $uploadsByKey[$normalizedNoSpaces] = $upload;
                }
            }
        }

        $updatedItems = [];
        foreach ($items as $item) {
            $id              = !empty($item['id']) ? (string)$item['id'] : (!empty($item['_id']) ? (string)$item['_id'] : '');
            $name            = trim($item['name'] ?? '');
            $normalizedName  = strtolower($name);
            $normalizedNoSpa = preg_replace('/\s+/', ' ', $normalizedName);

            $slot = null;
            if ($id && isset($uploadsByKey[$id])) {
                $slot = $uploadsByKey[$id];
            } elseif ($name && isset($uploadsByKey[$name])) {
                $slot = $uploadsByKey[$name];
            } elseif ($normalizedName && isset($uploadsByKey[$normalizedName])) {
                $slot = $uploadsByKey[$normalizedName];
            } elseif ($normalizedNoSpa && isset($uploadsByKey[$normalizedNoSpa])) {
                $slot = $uploadsByKey[$normalizedNoSpa];
            } else {
                foreach ($uploadsByKey as $key => $uploadData) {
                    if (!is_string($key) || empty($uploadData['itemName'])) {
                        continue;
                    }
                    $storedName          = strtolower(trim($uploadData['itemName']));
                    $storedNameNoSpaces  = preg_replace('/\s+/', ' ', $storedName);
                    if (
                        stripos($normalizedName, $storedName) !== false ||
                        stripos($storedName, $normalizedName) !== false ||
                        $normalizedNoSpa === $storedNameNoSpaces
                    ) {
                        $slot = $uploadData;
                        break;
                    }
                }
            }

            $description = (string)($item['description'] ?? '');
            if ($slot && !empty($slot['urls'])) {
                $qty  = isset($item['quantity']) ? (int)$item['quantity'] : (isset($item['qty']) ? (int)$item['qty'] : 1);
                $urls = array_slice($slot['urls'], 0, max(1, $qty));
                $imgs = array_map(function ($url) {
                    $safe = esc_url_raw($url);
                    return '<img src="' . $safe . '" width="170" style="border-radius:8px;margin:6px 0;display:block;">';
                }, $urls);
                $description = '<div style="margin:6px 0 10px 0">'
                    . '<div style="font-weight:600;color:#111827;margin-bottom:6px">Provided Image</div>'
                    . implode("\n", $imgs)
                    . '</div>';
            } else {
                $description = '<div style="font-weight:600;color:#6b7280">No photos provided</div>';
            }

            $qtyOut = isset($item['quantity']) ? (int)$item['quantity'] : (isset($item['qty']) ? (int)$item['qty'] : 1);

            $updatedItems[] = [
                'name'        => $item['name'] ?? '',
                'description' => $description,
                'currency'    => $item['currency'] ?? ($record['currency'] ?? 'AUD'),
                'amount'      => $item['amount'] ?? 0,
                'qty'         => $qtyOut,
            ];
        }

        // We need access to EstimateNormalizer for these methods
        // For now, inline the logic
        $normalizer = new EstimateNormalizer($this->config);

        return [
            'name'              => $normalizer->truncateName($record['name'] ?? $record['title'] ?? 'Estimate'),
            'title'             => $record['title'] ?? 'ESTIMATE',
            'businessDetails'   => $record['businessDetails'] ?? ['name' => 'Cheap Alarms'],
            'currency'          => $record['currency'] ?? ($record['currencyOptions']['code'] ?? 'USD'),
            'discount'          => $record['discount'] ?? ['type' => 'percentage', 'value' => 0],
            'contactDetails'    => $normalizer->extractContactDetails($record),
            'issueDate'         => $normalizer->formatDate($record['issueDate'] ?? null),
            'expiryDate'        => $normalizer->formatDate($record['expiryDate'] ?? null, '+30 days'),
            'frequencySettings' => $record['frequencySettings'] ?? ['enabled' => false],
            'liveMode'          => array_key_exists('liveMode', $record) ? (bool)$record['liveMode'] : true,
            'items'             => $updatedItems,
        ];
    }
}

