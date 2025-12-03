<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;

use function esc_url_raw;
use function get_option;
use function sanitize_email;
use function sanitize_text_field;
use function site_url;
use function update_option;
use function wp_json_encode;

class EstimateService
{
    public function __construct(
        private Config $config,
        private GhlClient $client,
        private Logger $logger
    ) {
    }

    /**
     * @return array|WP_Error
     */
    public function diagnostics(string $locationId)
    {
        $locationId = $locationId ?: $this->config->getLocationId();
        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID is not configured.', 'cheapalarms'));
        }

        $response = $this->client->get('/locations/' . rawurlencode($locationId));
        if (is_wp_error($response)) {
            return $response;
        }

        return [
            'ok'   => true,
            'code' => 200,
            'raw'  => $response,
        ];
    }

    /**
     * @param array<string, mixed> $args
     */
    /**
     * @return array|WP_Error
     */
    public function getEstimate(array $args)
    {
        $estimateId = sanitize_text_field($args['estimateId'] ?? '');
        $email      = sanitize_email($args['email'] ?? '');
        $locationId = sanitize_text_field($args['locationId'] ?? $this->config->getLocationId());
        $includeRaw = (int)($args['raw'] ?? 0);

        if (!$estimateId && !$email) {
            return new WP_Error('bad_request', __('Provide estimateId or email', 'cheapalarms'), ['status' => 400]);
        }

        if ($estimateId) {
            $record = $this->getEstimateById($estimateId, $locationId);
            if (is_wp_error($record)) {
                return $record;
            }
        } else {
            $record = $this->findLatestEstimateByEmail($email, $locationId, $err);
            if (is_wp_error($record)) {
                return $record;
            }
            if (!$record) {
                return new WP_Error('not_found', __('No estimate found for the provided email.', 'cheapalarms'), ['status' => 404]);
            }
        }

        if (!$record) {
            return new WP_Error('not_found', __('Estimate not found.', 'cheapalarms'), ['status' => 404]);
        }

        return $this->trimEstimate($record, $includeRaw);
    }

    /**
     * @return array|WP_Error
     */
    public function listEstimates(string $locationId, int $limit = 20, int $includeRaw = 0)
    {
        $locationId = $locationId ?: $this->config->getLocationId();
        $limit      = max(1, min(100, $limit));

        $out     = [];
        $rawAll  = [];
        $offset  = '0';

        while (count($out) < $limit) {
            $query = [
                'altId'   => $locationId,
                'altType' => 'location',
                'limit'   => min(50, $limit - count($out)),
                'offset'  => $offset,
            ];

            $response = $this->client->get('/invoices/estimate/list', $query);
            if (is_wp_error($response)) {
                return $response;
            }

            $records = $response['estimates'] ?? $response['items'] ?? [];
            foreach ($records as $record) {
                if ($includeRaw) {
                    $rawAll[] = $record;
                }

                $estimateId = $record['estimateId'] ?? $record['id'] ?? $record['_id'] ?? null;
                $email =
                    $record['contact']['email'] ??
                    $record['contactDetails']['email'] ??
                    ($record['sentTo']['email'][0] ?? '') ??
                    '';

                $status = $record['estimateStatus'] ?? $record['status'] ?? '';

                $portalMetaRaw = $estimateId ? get_option('ca_portal_meta_' . $estimateId, '{}') : '{}';
                $portalMeta    = json_decode(is_string($portalMetaRaw) ? $portalMetaRaw : '{}', true);
                $inviteToken   = $portalMeta['account']['inviteToken'] ?? null;

                $out[] = [
                    'id'             => $estimateId,
                    'estimateNumber' => $record['estimateNumber'] ?? null,
                    'email'          => $email,
                    'status'         => $status,
                    'total'          => (float)($record['total'] ?? 0),
                    'currency'       => $record['currency'] ?? 'AUD',
                    'createdAt'      => $record['createdAt'] ?? '',
                    'updatedAt'      => $record['updatedAt'] ?? '',
                    'inviteToken'    => $inviteToken,
                ];

                if (count($out) >= $limit) {
                    break 2;
                }
            }

            $next = $response['nextOffset'] ?? ($response['meta']['nextOffset'] ?? null);
            if (!$next) {
                break;
            }
            $offset = (string)$next;
        }

        $payload = [
            'ok'         => true,
            'locationId' => $locationId,
            'count'      => count($out),
            'items'      => $out,
        ];

        if ($includeRaw) {
            $payload['raw'] = $rawAll;
        }

        return $payload;
    }

    /**
     * @return array|WP_Error
     */
    public function findByContactEmail(string $email, string $locationId, int $includeRaw = 0)
    {
        $locationId = $locationId ?: $this->config->getLocationId();
        if (!$email) {
            return new WP_Error('bad_request', __('Email is required.', 'cheapalarms'), ['status' => 400]);
        }

        $record = $this->findLatestEstimateByEmail($email, $locationId, $err);
        if (is_wp_error($record)) {
            return $record;
        }

        if (!$record) {
            return new WP_Error('not_found', __('No estimates for that contact.', 'cheapalarms'), ['status' => 404]);
        }

        return $this->trimEstimate($record, $includeRaw);
    }

    /**
     * @param array<string, mixed> $payload
     */
    /**
     * @return array|WP_Error
     */
    public function createEstimate(array $payload)
    {
        if (empty($payload['altId'])) {
            $payload['altId'] = $this->config->getLocationId();
        }
        if (empty($payload['altType'])) {
            $payload['altType'] = 'location';
        }

        $response = $this->client->post('/invoices/estimate', $payload);
        if (is_wp_error($response)) {
            return $response;
        }

        $newId = $response['estimate']['id'] ?? $response['id'] ?? $response['_id'] ?? null;
        if ($newId) {
            $noteHtml = $this->buildPhotoBanner($newId);
            $this->appendTermsSafely($newId, $payload['altId'], $noteHtml, $payload['termsNotes'] ?? null);
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * @param array<string, mixed> $payload
     */
    /**
     * @return array|WP_Error
     */
    public function updateEstimate(array $payload)
    {
        $estimateId = $payload['estimateId'] ?? '';
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]);
        }

        $altId   = $payload['altId'] ?? $this->config->getLocationId();
        $altType = $payload['altType'] ?? 'location';
        
        // Extract revision data before removing estimateId
        $revisionData = $payload['revisionData'] ?? null;
        unset($payload['estimateId']);
        unset($payload['revisionData']); // Remove from GHL payload

        $existingTerms = (string)($payload['termsNotes'] ?? '');
        $payload['termsNotes'] = $this->ensurePhotoLinkInTerms($existingTerms, $estimateId);

        $response = $this->client->put(
            '/invoices/estimate/' . rawurlencode($estimateId),
            $payload,
            ['altId' => $altId],
            30, // timeout
            $altId // locationId header (GHL requires this for multi-location accounts)
        );

        if (is_wp_error($response)) {
            return $response;
        }

        // Store revision data in portal meta if provided
        if ($revisionData && is_array($revisionData)) {
            $portalService = $this->container->get(\CheapAlarms\Plugin\Services\PortalService::class);
            $portalService->storeRevisionData($estimateId, $revisionData);
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * @return array|WP_Error
     */
    public function createInvoiceFromEstimate(string $estimateId, string $locationId, array $options = [])
    {
        $payload = array_merge(
            [
                'altId'   => $locationId,
                'altType' => 'location',
            ],
            $options
        );

        $response = $this->client->post(
            '/invoices/estimate/' . rawurlencode($estimateId) . '/invoice',
            $payload,
            30,
            $locationId
        );

        if (is_wp_error($response)) {
            return $response;
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * Creates an invoice directly from draft estimate data (without requiring estimate to be accepted).
     * This bypasses the "estimate must be accepted" requirement.
     *
     * @return array|WP_Error
     */
    public function createInvoiceFromDraftEstimate(string $estimateId, string $locationId, array $options = [])
    {
        // Fetch the draft estimate
        $record = $this->getEstimateById($estimateId, $locationId);
        if (is_wp_error($record)) {
            return $record;
        }
        if (!$record) {
            return new WP_Error('not_found', __('Estimate not found.', 'cheapalarms'), ['status' => 404]);
        }

        // Extract contact details
        $contactDetails = $this->extractContactDetails($record);
        
        // Ensure contact has an ID (required for invoice creation)
        if (empty($contactDetails['id'])) {
            $this->logger->error('Cannot create invoice: estimate missing contact ID', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'contactDetails' => $contactDetails,
            ]);
            return new WP_Error('missing_contact_id', __('Contact ID is required to create invoice. Estimate must have a linked contact.', 'cheapalarms'), ['status' => 400]);
        }

        // Validate estimate has items
        $estimateItems = (array)($record['items'] ?? []);
        if (empty($estimateItems)) {
            $this->logger->error('Cannot create invoice: estimate has no items', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);
            return new WP_Error('empty_items', __('Cannot create invoice: estimate has no items.', 'cheapalarms'), ['status' => 400]);
        }

        // Validate and map items
        $invoiceItems = [];
        foreach ($estimateItems as $item) {
            // Validate item structure
            $itemName = (string)($item['name'] ?? '');
            $itemAmount = (float)($item['amount'] ?? 0);
            
            if (empty($itemName)) {
                $this->logger->warning('Skipping invoice item with missing name', [
                    'estimateId' => $estimateId,
                    'item' => $item,
                ]);
                continue; // Skip invalid items
            }
            
            if ($itemAmount <= 0) {
                $this->logger->warning('Invoice item has zero or negative amount', [
                    'estimateId' => $estimateId,
                    'itemName' => $itemName,
                    'amount' => $itemAmount,
                ]);
            }
            
            $invoiceItems[] = [
                'name'        => $itemName,
                'description' => (string)($item['description'] ?? ''),
                'currency'    => (string)($item['currency'] ?? ($record['currency'] ?? 'AUD')),
                'amount'      => $itemAmount,
                'qty'         => (int)(isset($item['quantity']) ? $item['quantity'] : ($item['qty'] ?? 1)),
            ];
        }
        
        // Ensure we have at least one valid item after validation
        if (empty($invoiceItems)) {
            $this->logger->error('Cannot create invoice: no valid items after validation', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'originalItemsCount' => count($estimateItems),
            ]);
            return new WP_Error('no_valid_items', __('Cannot create invoice: no valid items found.', 'cheapalarms'), ['status' => 400]);
        }

        // Build invoice payload from estimate data
        $invoicePayload = [
            'altId'          => $locationId,
            'altType'        => 'location',
            'name'           => mb_substr((string)($record['name'] ?? 'Invoice'), 0, 40),
            'title'          => 'INVOICE',
            'businessDetails' => (array)($record['businessDetails'] ?? ['name' => 'Cheap Alarms']),
            'currency'       => (string)($record['currency'] ?? ($record['currencyOptions']['code'] ?? 'AUD')),
            'contactDetails' => $contactDetails,
            'issueDate'      => gmdate('Y-m-d'),
            'dueDate'        => gmdate('Y-m-d', strtotime('+30 days')),
            'items'          => $invoiceItems,
            'termsNotes'     => (string)($record['termsNotes'] ?? ''),
        ];

        // Merge any additional options
        $invoicePayload = array_merge($invoicePayload, $options);

        // Create invoice using general invoice creation endpoint
        $response = $this->client->post(
            '/invoices/',
            $invoicePayload,
            30,
            $locationId
        );

        if (is_wp_error($response)) {
            return $response;
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * Send estimate via GHL API.
     *
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $options Optional options (method: 'email'|'sms', etc.)
     * @return array|WP_Error
     */
    public function sendEstimate(string $estimateId, string $locationId, array $options = [])
    {
        $estimateId = sanitize_text_field($estimateId);
        $locationId = sanitize_text_field($locationId ?: $this->config->getLocationId());

        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId is required to send.', 'cheapalarms'), ['status' => 400]);
        }

        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID required to send estimate.', 'cheapalarms'), ['status' => 400]);
        }

        $payload = array_merge([
            'altId'   => $locationId,
            'altType' => 'location',
        ], $options);

        // GHL API: POST /invoices/estimate/{id}/send
        $response = $this->client->post(
            '/invoices/estimate/' . rawurlencode($estimateId) . '/send',
            $payload,
            30,
            $locationId
        );

        if (is_wp_error($response)) {
            return $response;
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * Ensure an estimate is marked accepted within GHL.
     *
     * @return array|WP_Error
     */
    public function acceptEstimateStatus(string $estimateId, string $locationId, array $options = [])
    {
        $estimateId = sanitize_text_field($estimateId);
        $locationId = sanitize_text_field($locationId ?: $this->config->getLocationId());

        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId is required to accept.', 'cheapalarms'), ['status' => 400]);
        }

        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID required to accept estimate.', 'cheapalarms'), ['status' => 400]);
        }

        $payload = array_merge([
            'altId'   => $locationId,
            'altType' => 'location',
        ], $options);

        // Primary accept endpoint
        $response = $this->client->post(
            '/invoices/estimate/' . rawurlencode($estimateId) . '/accept',
            $payload,
            30,
            $locationId
        );

        if (is_wp_error($response)) {
            $data    = $response->get_error_data();
            $code    = isset($data['code']) ? (int) $data['code'] : 0;
            $payload['status'] = 'accepted';

            // Fallback to updating the estimate directly (older accounts/envs)
            if (in_array($code, [400, 404, 405], true)) {
                $payload['status'] = 'accepted';

                $fallback = $this->client->put(
                    '/invoices/estimate/' . rawurlencode($estimateId),
                    $payload,
                    ['altId' => $locationId, 'altType' => 'location'],
                    30,
                    $locationId
                );

                if (!is_wp_error($fallback)) {
                    return ['ok' => true, 'result' => $fallback, 'mode' => 'update'];
                }

                return $fallback;
            }

            return $response;
        }

        return ['ok' => true, 'result' => $response, 'mode' => 'accept'];
    }

    private function formatDate($value, ?string $fallback = null): string
    {
        if ($value) {
            $timestamp = is_numeric($value) ? (int) $value : strtotime((string) $value);
            if ($timestamp !== false) {
                return gmdate('Y-m-d', $timestamp);
            }
        }

        return $fallback ? gmdate('Y-m-d', strtotime($fallback)) : gmdate('Y-m-d');
    }

    /**
     * @param array<string, mixed> $data
     */
    /**
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
     * @param array<string, mixed> $payload
     */
    /**
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

        $record = $this->getEstimateById($estimateId, $locationId);
        if (is_wp_error($record)) {
            return $record;
        }
        if (!$record) {
            return new WP_Error('not_found', __('Estimate not found.', 'cheapalarms'), ['status' => 404]);
        }

        $updated = $this->mergePhotosIntoItems($record, $map);

        $payload = [
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

        return $this->updateEstimate($payload);
    }

    /**
     * @param array<string, mixed> $payload
     */
    /**
     * @return array|WP_Error
     */
    public function annotateEstimate(array $payload)
    {
        $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
        $locationId = sanitize_text_field($payload['locationId'] ?? $this->config->getLocationId());
        if (!$estimateId || !$locationId) {
            return new WP_Error('bad_request', __('estimateId and locationId required.', 'cheapalarms'), ['status' => 400]);
        }

        $record = $this->getEstimateById($estimateId, $locationId);
        if (is_wp_error($record)) {
            return $record;
        }
        if (!$record) {
            return new WP_Error('not_found', __('Estimate not found.', 'cheapalarms'), ['status' => 404]);
        }

        $payload = [
            'estimateId'        => $estimateId,
            'altId'             => $locationId,
            'altType'           => 'location',
            'name'              => mb_substr((string)($record['name'] ?? 'Estimate'), 0, 40),
            'title'             => (string)($record['title'] ?? 'ESTIMATE'),
            'businessDetails'   => (array)($record['businessDetails'] ?? ['name' => 'Cheap Alarms']),
            'currency'          => (string)($record['currency'] ?? ($record['currencyOptions']['code'] ?? 'USD')),
            'discount'          => (array)($record['discount'] ?? ['type' => 'percentage', 'value' => 0]),
            'contactDetails'    => $this->extractContactDetails($record),
            'issueDate'         => gmdate('Y-m-d', strtotime($record['issueDate'] ?? 'now')),
            'expiryDate'        => gmdate('Y-m-d', strtotime($record['expiryDate'] ?? '+30 days')),
            'frequencySettings' => (array)($record['frequencySettings'] ?? ['enabled' => false]),
            'liveMode'          => array_key_exists('liveMode', $record) ? (bool)$record['liveMode'] : true,
            'items'             => array_map(fn ($item) => [
                'name'        => (string)($item['name'] ?? ''),
                'description' => (string)($item['description'] ?? ''),
                'currency'    => (string)($item['currency'] ?? ($record['currency'] ?? 'USD')),
                'amount'      => (float)($item['amount'] ?? 0),
                'qty'         => (int)(isset($item['quantity']) ? $item['quantity'] : ($item['qty'] ?? 1)),
            ], (array)($record['items'] ?? [])),
            'termsNotes'        => $this->ensurePhotoLinkInTerms((string)($record['termsNotes'] ?? ''), $estimateId),
        ];

        return $this->updateEstimate($payload);
    }

    private function buildPhotoBanner(string $estimateId): string
    {
        $link = esc_url_raw(site_url('/upload?estimateId=' . rawurlencode($estimateId)));

        return '<p><strong>Upload photos for this estimate:</strong> '
            . '<a href="' . $link . '" target="_blank" rel="noopener">' . $link . '</a></p>';
    }

    private function ensurePhotoLinkInTerms(string $terms, string $estimateId): string
    {
        $link = '/upload?estimateId=';
        if (strpos($terms, $link) !== false) {
            return $terms;
        }

        return $this->buildPhotoBanner($estimateId) . "\n" . $terms;
    }

    private function appendTermsSafely(string $estimateId, string $locationId, string $noteHtml, ?string $termsFromCreate = null): void
    {
        $record = $this->getEstimateByIdWithRetry($estimateId, $locationId);
        if (!$record || is_wp_error($record)) {
            $this->logger->warning('Unable to fetch estimate for terms update', [
                'estimateId' => $estimateId,
            ]);
            return;
        }

        $existingTerms = '';
        if (!empty($record['termsNotes'])) {
            $existingTerms = $record['termsNotes'];
        } elseif (!empty($termsFromCreate)) {
            $existingTerms = $termsFromCreate;
        }
        $finalTerms = $noteHtml . "\n" . $existingTerms;

        $payload = [
            'estimateId'        => $estimateId,
            'altId'             => $locationId,
            'altType'           => 'location',
            'name'              => $this->truncateName($record['name'] ?? $record['title'] ?? 'Estimate'),
            'title'             => $record['title'] ?? 'ESTIMATE',
            'businessDetails'   => $record['businessDetails'] ?? ['name' => 'Cheap Alarms'],
            'currency'          => $record['currency'] ?? ($record['currencyOptions']['code'] ?? 'USD'),
            'discount'          => $record['discount'] ?? ['type' => 'percentage', 'value' => 0],
            'contactDetails'    => $this->extractContactDetails($record),
            'issueDate'         => $this->formatDate($record['issueDate'] ?? null),
            'expiryDate'        => $this->formatDate($record['expiryDate'] ?? null, '+30 days'),
            'frequencySettings' => $record['frequencySettings'] ?? ['enabled' => false],
            'liveMode'          => array_key_exists('liveMode', $record) ? (bool)$record['liveMode'] : true,
            'items'             => array_map(fn ($item) => [
                'name'        => (string)($item['name'] ?? ''),
                'description' => (string)($item['description'] ?? ''),
                'currency'    => (string)($item['currency'] ?? ($record['currency'] ?? 'USD')),
                'amount'      => (float)($item['amount'] ?? 0),
                'qty'         => (int)(isset($item['quantity']) ? $item['quantity'] : ($item['qty'] ?? 1)),
            ], (array)($record['items'] ?? [])),
            'termsNotes'        => $finalTerms,
        ];

        $this->updateEstimate($payload);
    }

    /**
     * @return array|WP_Error|null
     */
    private function getEstimateById(string $estimateId, string $locationId)
    {
        if (!$locationId) {
            return new WP_Error('missing_location', __('locationId required', 'cheapalarms'));
        }

        $response = $this->client->get(
            '/invoices/estimate/' . rawurlencode($estimateId),
            ['altId' => $locationId, 'altType' => 'location', 'raw' => 1]
        );
        if (is_wp_error($response)) {
            $data = $response->get_error_data();
            $code = $data['code'] ?? null;
            if ($code && (int)$code !== 404) {
                return $response;
            }
        } else {
            if (isset($response['estimate'])) {
                return $response['estimate'];
            }

            if (!empty($response)) {
                return $response;
            }
        }

        // fallback: list + filter
        $offset = '0';
        $loops = 0;
        do {
            $loops++;
            if ($loops > 20) {
                break;
            }
            $query = ['altId' => $locationId, 'altType' => 'location', 'limit' => 50, 'offset' => $offset];
            $list = $this->client->get('/invoices/estimate/list', $query);
            if (is_wp_error($list)) {
                return $list;
            }

            $records = $list['estimates'] ?? $list['items'] ?? [];
            foreach ($records as $record) {
                $rid = $record['id'] ?? $record['_id'] ?? $record['estimateId'] ?? null;
                if ($rid && $rid === $estimateId) {
                    return $record;
                }
            }

            $next = $list['nextOffset'] ?? ($list['meta']['nextOffset'] ?? null);
            $offset = $next ? (string)$next : null;
        } while ($offset !== null);

        return null;
    }

    /**
     * @return array|WP_Error|null
     */
    private function getEstimateByIdWithRetry(string $estimateId, string $locationId)
    {
        $tries = 0;
        do {
            $tries++;
            $record = $this->getEstimateById($estimateId, $locationId);
            if ($record && !is_wp_error($record)) {
                return $record;
            }
            if ($tries >= 6) {
                return $record;
            }
            usleep(300000);
        } while (true);
    }

    /**
     * @return array|WP_Error|null
     */
    private function findLatestEstimateByEmail(string $email, string $locationId, &$err = null)
    {
        $contactId = $this->findContactIdByEmail($email, $locationId);
        if (is_wp_error($contactId)) {
            return $contactId;
        }
        if (!$contactId) {
            return null;
        }

        $match  = null;
        $offset = '0';
        $loops  = 0;
        do {
            $loops++;
            if ($loops > 20) {
                break;
            }
            $query = ['altId' => $locationId, 'altType' => 'location', 'limit' => 50, 'offset' => $offset];
            $response = $this->client->get('/invoices/estimate/list', $query);
            if (is_wp_error($response)) {
                return $response;
            }

            $records = $response['estimates'] ?? $response['items'] ?? [];
            foreach ($records as $record) {
                $cid = $record['contact']['id'] ?? ($record['contactId'] ?? '');
                if ($cid && $cid === $contactId) {
                    if (!$match) {
                        $match = $record;
                    } else {
                        $a = strtotime($match['updatedAt'] ?? $match['createdAt'] ?? 'now');
                        $b = strtotime($record['updatedAt'] ?? $record['createdAt'] ?? 'now');
                        if ($b > $a) {
                            $match = $record;
                        }
                    }
                }
            }

            $next = $response['nextOffset'] ?? ($response['meta']['nextOffset'] ?? null);
            $offset = $next ? (string)$next : null;
        } while (!$match && $offset !== null);

        return $match;
    }

    /**
     * @return string|WP_Error|null
     */
    private function findContactIdByEmail(string $email, string $locationId)
    {
        $response = $this->client->get('/contacts/search', [
            'locationId' => $locationId,
            'query'      => $email,
        ], 20);

        if (is_wp_error($response)) {
            return $response;
        }

        $contacts = $response['contacts'] ?? $response['items'] ?? [];
        foreach ($contacts as $contact) {
            $contactEmail = $contact['email'] ?? '';
            if ($contactEmail && strcasecmp($contactEmail, $email) === 0) {
                return $contact['id'] ?? null;
            }
        }

        return null;
    }

    private function truncateName(string $name): string
    {
        $name = trim($name);
        if ($name === '') {
            $name = 'Estimate';
        }
        return mb_substr($name, 0, 40);
    }

    /**
     * @param array<string, mixed> $record
     */
    private function extractContactDetails(array $record): array
    {
        $contact = $record['contactDetails'] ?? null;
        if ($contact) {
            return $contact;
        }

        $c = $record['contact'] ?? [];
        return [
            'id'      => $c['id'] ?? ($record['contactId'] ?? ''),
            'name'    => trim(($c['firstName'] ?? '') . ' ' . ($c['lastName'] ?? '')),
            'email'   => $c['email'] ?? '',
            'phoneNo' => $c['phone'] ?? '',
        ];
    }

    /**
     * @param array<string, mixed> $record
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

        return [
            'name'              => $this->truncateName($record['name'] ?? $record['title'] ?? 'Estimate'),
            'title'             => $record['title'] ?? 'ESTIMATE',
            'businessDetails'   => $record['businessDetails'] ?? ['name' => 'Cheap Alarms'],
            'currency'          => $record['currency'] ?? ($record['currencyOptions']['code'] ?? 'USD'),
            'discount'          => $record['discount'] ?? ['type' => 'percentage', 'value' => 0],
            'contactDetails'    => $this->extractContactDetails($record),
            'issueDate'         => $this->formatDate($record['issueDate'] ?? null),
            'expiryDate'        => $this->formatDate($record['expiryDate'] ?? null, '+30 days'),
            'frequencySettings' => $record['frequencySettings'] ?? ['enabled' => false],
            'liveMode'          => array_key_exists('liveMode', $record) ? (bool)$record['liveMode'] : true,
            'items'             => $updatedItems,
        ];
    }

    /**
     * @param array<string, mixed> $record
     */
    private function trimEstimate(array $record, int $includeRaw = 0): array
    {
        $items = [];
        foreach (($record['items'] ?? []) as $item) {
            $qty = isset($item['quantity']) ? (int)$item['quantity'] : (isset($item['qty']) ? (int)$item['qty'] : 1);
            $items[] = [
                'id'                  => $item['id'] ?? ($item['_id'] ?? null),
                'name'                => $item['name'] ?? '',
                'sku'                 => $item['sku'] ?? '',
                'qty'                 => $qty,
                'description'         => $item['description'] ?? '',
                'originalDescription' => $item['description'] ?? '',
                'amount'              => $item['amount'] ?? null,
                'currency'            => $item['currency'] ?? null,
            ];
        }

        $contact = [
            'id'        => $record['contact']['id'] ?? ($record['contactId'] ?? ''),
            'firstName' => $record['contact']['firstName'] ?? '',
            'lastName'  => $record['contact']['lastName'] ?? '',
            'email'     => $record['contact']['email'] ?? '',
            'phone'     => $record['contact']['phone'] ?? '',
        ];
        if (empty($contact['email']) && !empty($record['contactDetails']['email'])) {
            $contact = [
                'id'      => $record['contactDetails']['id'] ?? '',
                'name'    => $record['contactDetails']['name'] ?? '',
                'email'   => $record['contactDetails']['email'] ?? '',
                'phone'   => $record['contactDetails']['phoneNo'] ?? '',
                'address' => $record['contactDetails']['address'] ?? null,
            ];
        }

        $payload = [
            'ok'             => true,
            'estimateId'     => $record['id'] ?? ($record['_id'] ?? null),
            'estimateNumber' => $record['estimateNumber'] ?? null,
            'status'         => $record['estimateStatus'] ?? $record['status'] ?? null,
            'title'          => $record['title'] ?? $record['name'] ?? 'Estimate',
            'contact'        => $contact,
            'items'          => $items,
            'currency'       => $record['currency'] ?? 'AUD',
            'subtotal'       => $record['subTotal'] ?? null,
            'taxTotal'       => $record['taxTotal'] ?? null,
            'total'          => $record['total'] ?? null,
            'createdAt'      => $record['createdAt'] ?? null,
            'updatedAt'      => $record['updatedAt'] ?? null,
        ];

        if ($includeRaw) {
            $payload['raw'] = $record;
        }

        return $payload;
    }
}

