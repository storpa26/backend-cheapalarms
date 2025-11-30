<?php

namespace CheapAlarms\Plugin\Services;

use WP_Error;
use WP_User;

use function add_query_arg;
use function apply_filters;
use function current_time;
use function __;
use function esc_html;
use function esc_url;
use function email_exists;
use function get_option;
use function get_user_meta;
use function get_password_reset_key;
use function get_user_by;
use function home_url;
use function is_wp_error;
use function sanitize_email;
use function sanitize_text_field;
use function update_option;
use function update_user_meta;
use function user_can;
use function wp_create_user;
use function wp_generate_password;
use function wp_mail;
use function wp_login_url;
use function wp_update_user;

class PortalService
{
    private const OPTION_PREFIX = 'ca_portal_meta_';

    public function __construct(
        private EstimateService $estimateService,
        private Logger $logger,
        private \CheapAlarms\Plugin\Services\Container $container
    ) {
    }

    public function getDashboardData(\WP_User $user): array
    {
        if (!$user || 0 === $user->ID) {
            return ['estimates' => []];
        }

        $raw = $this->getDashboardForUser((int) $user->ID);
        $estimates = [];

        foreach ($raw as $item) {
            $estimates[] = [
                'estimateId'   => $item['estimateId'] ?? null,
                'locationId'   => $item['locationId'] ?? null,
                'status'       => $item['quote']['status'] ?? 'pending',
                'statusLabel'  => $item['quote']['statusLabel'] ?? 'Pending',
                'number'       => $item['quote']['number'] ?? ($item['estimateId'] ?? null),
                'acceptedAt'   => $item['quote']['acceptedAt'] ?? null,
                'portalUrl'    => $item['account']['portalUrl'] ?? null,
                'resetUrl'     => $item['account']['resetUrl'] ?? null,
                'lastInviteAt' => $item['account']['lastInviteAt'] ?? null,
                'invoice'      => $item['invoice'] ?? null,
            ];
        }

        return [
            'estimates' => $estimates,
        ];
    }

    private function generateToken(): string
    {
        return wp_generate_password(48, false, false);
    }

    private function resolvePortalUrl(string $estimateId, ?string $token = null): string
    {
        $base = apply_filters('cheapalarms_portal_base_url', home_url('/portal'));
        $args = ['estimateId' => $estimateId];
        if ($token) {
            $args['inviteToken'] = $token;
        }

        return add_query_arg($args, $base);
    }

    /**
     * @return array|WP_Error
     */
    public function getStatus(string $estimateId, string $locationId, ?string $inviteToken = null, ?WP_User $user = null)
    {
        $meta = $this->getMeta($estimateId);

        if ($inviteToken && !$this->validateInviteToken($estimateId, $inviteToken)) {
            return new WP_Error('invalid_invite', __('The invite link is no longer valid.', 'cheapalarms'), ['status' => 403]);
        }

        $effectiveLocation = $locationId ?: ($meta['locationId'] ?? '');

        if ($user instanceof WP_User && $user->ID > 0 && !$inviteToken && !user_can($user, 'manage_options')) {
            $linked = get_user_meta($user->ID, 'ca_estimate_ids', true);
            if (!is_array($linked)) {
                $linked = array_filter([$linked]);
            }
            if (!in_array($estimateId, $linked, true)) {
                return new WP_Error(
                    'forbidden_estimate',
                    __('This estimate is not linked to your account.', 'cheapalarms'),
                    ['status' => 403]
                );
            }

            if (!$effectiveLocation) {
                $locations = get_user_meta($user->ID, 'ca_estimate_locations', true);
                if (is_array($locations) && isset($locations[$estimateId])) {
                    $effectiveLocation = $locations[$estimateId];
                }
            }
        }

        $estimate = $this->estimateService->getEstimate([
            'estimateId' => $estimateId,
            'locationId' => $effectiveLocation,
        ]);
        if (is_wp_error($estimate)) {
            return $estimate;
        }

        if ($effectiveLocation) {
            $meta['locationId'] = $effectiveLocation;
            $this->updateMeta($estimateId, ['locationId' => $effectiveLocation]);
        }
        $locationId = $effectiveLocation;

        $estimateStatus = $estimate['status'] ?? '';
        $isAccepted     = $estimateStatus === 'accepted';

        $quoteStatus = [
            'status'      => $isAccepted ? 'accepted' : 'pending',
            'statusLabel' => $isAccepted ? 'Accepted via GHL' : 'Awaiting approval',
            'number'      => $estimate['estimateNumber'] ?? $estimate['estimateId'],
            'acceptedAt'  => $meta['quote']['acceptedAt'] ?? null,
            'canAccept'   => false,
        ];
        if ($isAccepted && empty($quoteStatus['acceptedAt'])) {
            $quoteStatus['acceptedAt'] = current_time('mysql');
        }

        $this->updateMeta($estimateId, ['quote' => $quoteStatus]);
        $meta = $this->getMeta($estimateId);

        $defaultAccount = [
            'status'      => 'pending',
            'statusLabel' => 'Invite pending',
            'lastInviteAt'=> null,
            'canResend'   => true,
            'portalUrl'   => null,
            'inviteToken' => null,
            'expiresAt'   => null,
            'userId'      => null,
            'resetUrl'    => null,
        ];

        $accountMeta = array_merge($defaultAccount, $meta['account'] ?? []);

        if ($isAccepted && ($accountMeta['status'] ?? '') !== 'active') {
            $provisioned = $this->provisionAccount($estimateId, $estimate['contact'] ?? [], $locationId);
            if (!is_wp_error($provisioned)) {
                $meta        = $this->getMeta($estimateId);
                $accountMeta = array_merge($defaultAccount, $meta['account'] ?? []);
            } else {
                $this->logger->error('Failed to auto-provision portal account', [
                    'estimateId' => $estimateId,
                    'error'      => $provisioned->get_error_message(),
                ]);
            }
        } elseif ($isAccepted && ($accountMeta['status'] ?? '') === 'active' && !empty($accountMeta['userId'])) {
            $this->attachEstimateToUser((int) $accountMeta['userId'], $estimateId, $locationId);
        }

        return [
            'estimateId'   => $estimateId,
            'locationId'   => $locationId, // Include locationId so frontend can use it for GHL sync
            'quote'        => $quoteStatus,
            'photos'       => $meta['photos'] ?? ['total' => 0, 'required' => 6, 'missingCount' => 6, 'items' => []],
            'installation' => $meta['installation'] ?? ['status' => 'pending', 'statusLabel' => 'Not scheduled', 'message' => null, 'canSchedule' => $quoteStatus['status'] === 'accepted'],
            'documents'    => $meta['documents'] ?? [],
            'account'      => $accountMeta,
            'invoice'      => $meta['invoice'] ?? null,
        ];
    }

    /**
     * @return array|WP_Error
     */
    public function acceptEstimate(string $estimateId, string $locationId = '')
    {
        $status = [
            'status'      => 'accepted',
            'statusLabel' => 'Accepted',
            'acceptedAt'  => current_time('mysql'),
            'canAccept'   => false,
        ];

        // Update WordPress meta first (always succeeds)
        $this->updateMeta($estimateId, ['quote' => $status]);

        // Get locationId from meta if not provided (locationId should be stored in meta from getStatus)
        if (empty($locationId)) {
            $meta = $this->getMeta($estimateId);
            $locationId = $meta['locationId'] ?? '';
        }

        // Update GHL signals (non-blocking - errors don't fail acceptance)
        if ($locationId) {
            $this->updateGhlSignals($estimateId, $locationId);
        }

        return [
            'ok'        => true,
            'quote'     => $status,
            'ghlSynced' => false,
            'ghlError'  => null,
        ];
    }

    /**
     * Update GHL signals (tags, notes) when estimate is accepted.
     * This is fire-and-forget: errors are logged but don't block acceptance.
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     */
    private function updateGhlSignals(string $estimateId, string $locationId): void
    {
        try {
            // Fetch estimate to get contact ID and details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Failed to fetch estimate for GHL signals', [
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contactId = $estimate['contact']['id'] ?? null;
            if (!$contactId) {
                $this->logger->warning('Estimate missing contact ID for GHL signals', [
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                return;
            }

            // Get signal service
            $signalService = $this->container->get(\CheapAlarms\Plugin\Services\GhlSignalService::class);

            // Prepare note data
            $estimateNumber = $estimate['estimateNumber'] ?? $estimateId;
            $acceptedAt = current_time('mysql');
            $noteData = [
                'estimateNumber' => $estimateNumber,
                'estimateId' => $estimateId,
                'acceptedAt' => $acceptedAt,
                'invoiceNumber' => null, // Will be updated after invoice creation
            ];

            // Fire-and-forget: Try both updates, log errors, move on
            $tagResult = $signalService->addAcceptanceTag($contactId, $locationId);
            if (is_wp_error($tagResult)) {
                $this->logger->warning('Failed to add GHL acceptance tag', [
                    'contactId' => $contactId,
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'error' => $tagResult->get_error_message(),
                ]);
            }

            $noteResult = $signalService->addAcceptanceNote($contactId, $locationId, $noteData);
            if (is_wp_error($noteResult)) {
                $this->logger->warning('Failed to add GHL acceptance note', [
                    'contactId' => $contactId,
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'error' => $noteResult->get_error_message(),
                ]);
            }

        } catch (\Exception $e) {
            // Catch any unexpected exceptions - don't let them break acceptance
            $this->logger->error('Exception updating GHL signals', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'exception' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Update GHL note with invoice information after invoice is created.
     * This is fire-and-forget: errors are logged but don't block invoice creation.
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $invoice Invoice data
     */
    private function updateGhlNoteWithInvoice(string $estimateId, string $locationId, array $invoice): void
    {
        try {
            // Fetch estimate to get contact ID
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Failed to fetch estimate for GHL invoice note update', [
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contactId = $estimate['contact']['id'] ?? null;
            if (!$contactId) {
                $this->logger->warning('Estimate missing contact ID for GHL invoice note update', [
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                return;
            }

            // Get signal service
            $signalService = $this->container->get(\CheapAlarms\Plugin\Services\GhlSignalService::class);

            // Add invoice info to note
            $invoiceNumber = $invoice['number'] ?? $invoice['id'] ?? '';
            $result = $signalService->updateAcceptanceNoteWithInvoice(
                $contactId,
                $locationId,
                $estimateId,
                $invoiceNumber
            );

            if (is_wp_error($result)) {
                $this->logger->warning('Failed to update GHL note with invoice info', [
                    'contactId' => $contactId,
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'invoiceNumber' => $invoiceNumber,
                    'error' => $result->get_error_message(),
                ]);
            }

        } catch (\Exception $e) {
            // Catch any unexpected exceptions - don't let them break invoice creation
            $this->logger->error('Exception updating GHL note with invoice', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'exception' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @return array|WP_Error
     */
    public function rejectEstimate(string $estimateId, string $locationId = '', string $reason = '')
    {
        $status = [
            'status'         => 'rejected',
            'statusLabel'    => 'Rejected',
            'rejectedAt'     => current_time('mysql'),
            'rejectionReason' => sanitize_text_field($reason),
            'canAccept'      => false,
        ];

        // Update WordPress meta first
        $this->updateMeta($estimateId, ['quote' => $status]);

        // Get locationId from meta if not provided
        if (empty($locationId)) {
            $meta = $this->getMeta($estimateId);
            $locationId = $meta['locationId'] ?? '';
        }

        return [
            'ok'        => true,
            'quote'     => $status,
            'ghlSynced' => false,
            'ghlError'  => null,
        ];
    }

    /**
     * Creates a GHL invoice for the provided estimate and caches the metadata locally.
     * Creates invoice directly from draft estimate data (estimate stays as draft in GHL).
     *
     * @param array<string, mixed> $options
     * @return array|WP_Error
     */
    public function createInvoiceForEstimate(string $estimateId, ?string $locationId = null, array $options = [])
    {
        $meta  = $this->getMeta($estimateId);
        $force = !empty($options['force']);
        unset($options['force']);

        if (!$force && !empty($meta['invoice']['id'])) {
            return [
                'invoice' => $meta['invoice'],
                'exists'  => true,
            ];
        }

        $resolvedLocation = $locationId ?: ($meta['locationId'] ?? '');
        if (!$resolvedLocation) {
            return new WP_Error('missing_location', __('Location ID required to create invoice.', 'cheapalarms'), ['status' => 400]);
        }

        // Create invoice directly from draft estimate (no need to accept estimate first)
        $response = $this->estimateService->createInvoiceFromDraftEstimate($estimateId, $resolvedLocation, $options);
        if (is_wp_error($response)) {
            return $response;
        }

        $payload = $response['result'] ?? [];
        $invoice = $this->normaliseInvoiceResponse($payload);

        if (!$invoice['id']) {
            $this->logger->warning('GHL invoice response missing identifier', [
                'estimateId' => $estimateId,
                'payload'    => $payload,
            ]);
        }

        $this->updateMeta($estimateId, ['invoice' => $invoice]);

        // Update GHL note with invoice information (non-blocking)
        if (!empty($invoice['id']) && $resolvedLocation) {
            $this->updateGhlNoteWithInvoice($estimateId, $resolvedLocation, $invoice);
        }

        return [
            'invoice' => $invoice,
        ];
    }

    private function extractGhlErrorMessage(WP_Error $error): string
    {
        $payload = $this->parseGhlErrorPayload($error);

        if (!empty($payload['message']) && is_string($payload['message'])) {
            return $payload['message'];
        }

        if (!empty($payload['error']) && is_string($payload['error'])) {
            return $payload['error'];
        }

        return $error->get_error_message();
    }

    private function isAlreadyAcceptedError(WP_Error $error): bool
    {
        $payload = $this->parseGhlErrorPayload($error);
        $code    = strtolower((string)($payload['code'] ?? $payload['error'] ?? ''));
        $message = strtolower((string)($payload['message'] ?? ''));

        if ($code && str_contains($code, 'already')) {
            return true;
        }

        return $message && str_contains($message, 'already accepted');
    }

    /**
     * @return array<string, mixed>
     */
    private function parseGhlErrorPayload(WP_Error $error): array
    {
        $data = $error->get_error_data();
        $body = $data['body'] ?? '';

        if (is_string($body) && $body !== '') {
            $decoded = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                return $decoded;
            }
        }

        return [];
    }

    private function normaliseInvoiceResponse(array $payload): array
    {
        $invoice = $payload['invoice'] ?? $payload;

        $id = $invoice['id']
            ?? $invoice['_id']
            ?? $invoice['invoiceId']
            ?? null;

        $url = $invoice['liveUrl']
            ?? $invoice['invoiceUrl']
            ?? $invoice['url']
            ?? null;

        return [
            'id'        => $id,
            'number'    => $invoice['invoiceNumber'] ?? $invoice['number'] ?? null,
            'status'    => $invoice['status'] ?? 'pending',
            'url'       => $url,
            'total'     => $invoice['total'] ?? null,
            'currency'  => $invoice['currency'] ?? 'USD',
            'createdAt' => $invoice['createdAt'] ?? current_time('mysql'),
            'raw'       => $payload,
        ];
    }

    /**
     * @return array|WP_Error
     */
    public function provisionAccount(string $estimateId, array $contact, ?string $locationId = null)
    {
        $email = sanitize_email($contact['email'] ?? '');
        if (!$email) {
            return new WP_Error('missing_contact', __('Contact email is required to create an account.', 'cheapalarms'), ['status' => 400]);
        }

        $firstName = sanitize_text_field($contact['firstName'] ?? $contact['name'] ?? '');
        $lastName  = sanitize_text_field($contact['lastName'] ?? '');

        $userId = email_exists($email);
        $password = null;
        if (!$userId) {
            $password = wp_generate_password(20);
            $userId = wp_create_user($email, $password, $email);
            if (is_wp_error($userId)) {
                return $userId;
            }
            wp_update_user([
                'ID'         => $userId,
                'first_name' => $firstName,
                'last_name'  => $lastName,
            ]);
        }

        wp_update_user(['ID' => $userId, 'role' => 'customer']);
        $this->attachEstimateToUser((int) $userId, $estimateId, $locationId);

        $token     = $this->generateToken();
        $expiresAt = current_time('timestamp') + DAY_IN_SECONDS * 7;
        $portalUrl = $this->resolvePortalUrl($estimateId, $token);

        $accountMeta = [
            'status'      => 'active',
            'statusLabel' => 'Account active',
            'lastInviteAt'=> current_time('mysql'),
            'canResend'   => true,
            'portalUrl'   => $portalUrl,
            'inviteToken' => $token,
            'expiresAt'   => gmdate('c', $expiresAt),
            'userId'      => (int) $userId,
            'locationId'  => $locationId,
        ];

        $update = ['account' => $accountMeta];
        if ($locationId) {
            $update['locationId'] = $locationId;
        }
        $this->updateMeta($estimateId, $update);

        $displayName = sanitize_text_field($firstName ?: ($contact['name'] ?? 'customer'));

        $resetUrl = $this->sendPortalInvite(
            $email,
            $displayName,
            $portalUrl,
            (int) $userId,
            false
        );

        if ($resetUrl) {
            $accountMeta['resetUrl'] = $resetUrl;
            $this->updateMeta($estimateId, ['account' => $accountMeta]);
        }

        $this->logger->info('Portal account provisioned', [
            'estimateId' => $estimateId,
            'userId'     => $userId,
            'resetUrl'   => $resetUrl,
        ]);

        return [
            'ok'      => true,
            'userId'  => $userId,
            'account' => $accountMeta,
        ];
    }

    /**
     * Link estimate to existing account without provisioning
     * @return array|WP_Error
     */
    public function linkEstimateToExistingAccount(string $estimateId, int $userId, ?string $locationId = null): array|WP_Error
    {
        // Attach estimate to user
        $this->attachEstimateToUser($userId, $estimateId, $locationId);
        
        // Get user info
        $user = get_user_by('id', $userId);
        if (!$user) {
            return new WP_Error('user_not_found', __('User not found.', 'cheapalarms'), ['status' => 404]);
        }
        
        // Update meta but don't send email (user already has account)
        $this->updateMeta($estimateId, [
            'account' => [
                'status' => 'active',
                'statusLabel' => 'Account active',
                'userId' => $userId,
                'locationId' => $locationId,
            ],
            'locationId' => $locationId,
        ]);
        
        $this->logger->info('Estimate linked to existing account', [
            'estimateId' => $estimateId,
            'userId' => $userId,
        ]);
        
        return [
            'ok' => true,
            'userId' => $userId,
            'message' => 'Estimate linked to existing account.',
        ];
    }

    /**
     * @return array|WP_Error
     */
    public function resendInvite(string $estimateId, array $contact)
    {
        $email = sanitize_email($contact['email'] ?? '');
        if (!$email) {
            return new WP_Error('missing_contact', __('Contact email is required to resend invite.', 'cheapalarms'), ['status' => 400]);
        }

        $currentMeta = $this->getMeta($estimateId)['account'] ?? [];
        $token       = $currentMeta['inviteToken'] ?? $this->generateToken();
        $portalLink  = $this->resolvePortalUrl($estimateId, $token);

        $userId      = isset($currentMeta['userId']) ? (int) $currentMeta['userId'] : (int) email_exists($email);
        $contactName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'customer');

        $resetUrl = $this->sendPortalInvite(
            $email,
            $contactName,
            $portalLink,
            $userId,
            true
        );

        $this->updateMeta($estimateId, [
            'account' => array_merge($currentMeta, [
                'lastInviteAt' => current_time('mysql'),
                'status'       => $currentMeta['status'] ?? 'pending',
                'statusLabel'  => ($currentMeta['status'] ?? '') === 'active' ? 'Account active' : 'Invite sent',
                'canResend'    => true,
                'inviteToken'  => $token,
                'portalUrl'    => $portalLink,
                'expiresAt'    => gmdate('c', current_time('timestamp') + DAY_IN_SECONDS * 7),
                'userId'       => $userId ?: ($currentMeta['userId'] ?? null),
                'resetUrl'     => $resetUrl ?: ($currentMeta['resetUrl'] ?? null),
            ]),
        ]);

        if ($userId) {
            $this->attachEstimateToUser($userId, $estimateId, $currentMeta['locationId'] ?? null);
        }

        return ['ok' => true];
    }

    /**
     * @return array<string, mixed>
     */
    private function getDashboardForUser(int $userId): array
    {
        $estimateIds = get_user_meta($userId, 'ca_estimate_ids', true);
        if (!is_array($estimateIds)) {
            $estimateIds = array_filter([$estimateIds]);
        }

        $locations = get_user_meta($userId, 'ca_estimate_locations', true);
        if (!is_array($locations)) {
            $locations = [];
        }

        // Get the user object to pass to getStatus
        $user = get_user_by('id', $userId);
        if (!$user) {
            return [];
        }

        $items = [];
        foreach (array_unique($estimateIds) as $estimateId) {
            if (!$estimateId) {
                continue;
            }

            $locationId = $locations[$estimateId] ?? '';
            // Pass the user object to getStatus so it can properly check permissions
            $status     = $this->getStatus($estimateId, $locationId, null, $user);
            if (is_wp_error($status)) {
                continue;
            }

            $items[] = array_merge($status, [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);
        }

        return $items;
    }

    /**
     * @return array<string, mixed>
     */
    private function getMeta(string $estimateId): array
    {
        $stored = get_option(self::OPTION_PREFIX . $estimateId, '{}');
        $decoded = json_decode($stored, true);
        if (!is_array($decoded)) {
            return [];
        }
        return $decoded;
    }

    private function updateMeta(string $estimateId, array $changes): void
    {
        $current = $this->getMeta($estimateId);
        $merged  = array_merge($current, $changes);
        update_option(self::OPTION_PREFIX . $estimateId, wp_json_encode($merged), false);
    }

    public function validateInviteToken(string $estimateId, string $token): bool
    {
        if (!$estimateId || !$token) {
            return false;
        }

        $accountToken = $this->getMeta($estimateId)['account']['inviteToken'] ?? null;

        return is_string($accountToken) && hash_equals($accountToken, $token);
    }

    private function sendPortalInvite(string $email, string $name, string $portalUrl, int $userId, bool $isResend): ?string
    {
        if (!$email || !$userId) {
            return null;
        }

        $user = get_user_by('id', $userId);
        if (!$user) {
            return null;
        }

        $subject = $isResend
            ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
            : __('Your CheapAlarms portal is ready', 'cheapalarms');

        $key = get_password_reset_key($user);
        $resetUrl = null;
        if (!is_wp_error($key)) {
            $resetUrl = add_query_arg(
                [
                    'action' => 'rp',
                    'key'    => $key,
                    'login'  => rawurlencode($user->user_login),
                ],
                wp_login_url()
            );
        }

        $headers  = ['Content-Type: text/html; charset=UTF-8'];
        $greeting = sprintf(__('Hi %s,', 'cheapalarms'), $name);

        $body  = '<p>' . esc_html($greeting) . '</p>';
        $body .= '<p>' . esc_html(__('We have prepared your CheapAlarms portal. Use the secure links below to access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
        $body .= '<p><a href="' . esc_url($portalUrl) . '">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';

        if ($resetUrl) {
            $body .= '<p><a href="' . esc_url($resetUrl) . '">' . esc_html(__('Set or reset your password', 'cheapalarms')) . '</a></p>';
        } else {
            $body .= '<p>' . esc_html(__('If you need to reset your password, use the "Forgot password?" link on the login page.', 'cheapalarms')) . '</p>';
        }

        $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
        $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';

        wp_mail($email, $subject, $body, $headers);

        $this->logger->info('Portal invite email sent', [
            'email'    => $email,
            'userId'   => $userId,
            'resend'   => $isResend,
            'resetUrl' => $resetUrl,
        ]);

        return $resetUrl;
    }

    private function attachEstimateToUser(int $userId, string $estimateId, ?string $locationId = null): void
    {
        $existing = get_user_meta($userId, 'ca_estimate_ids', true);
        if (!is_array($existing)) {
            $existing = [];
        }
        if (!in_array($estimateId, $existing, true)) {
            $existing[] = $estimateId;
        }
        update_user_meta($userId, 'ca_estimate_ids', array_values(array_unique($existing)));
        update_user_meta($userId, 'ca_estimate_id', $estimateId);

        if ($locationId) {
            $locations = get_user_meta($userId, 'ca_estimate_locations', true);
            if (!is_array($locations)) {
                $locations = [];
            }
            $locations[$estimateId] = $locationId;
            update_user_meta($userId, 'ca_estimate_locations', $locations);
        }
    }
}

