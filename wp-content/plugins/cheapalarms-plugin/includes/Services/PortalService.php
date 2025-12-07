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
use function get_user_by;
use function get_password_reset_key;
use function home_url;
use function is_wp_error;
use function rawurlencode;
use function sanitize_email;
use function sanitize_text_field;
use function trailingslashit;
use function update_option;
use function update_user_meta;
use function user_can;
use function wp_create_user;
use function wp_generate_password;
use function wp_mail;
use function wp_update_user;

class PortalService
{
    private const OPTION_PREFIX = 'ca_portal_meta_';

    public function __construct(
        private EstimateService $estimateService,
        private Logger $logger,
        private \CheapAlarms\Plugin\Services\Container $container,
        private \CheapAlarms\Plugin\Config\Config $config
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
                'status'       => $item['quote']['status'] ?? 'sent',
                'statusLabel'  => $item['quote']['statusLabel'] ?? 'Sent',
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
        // Use frontend URL (Next.js on Vercel) instead of WordPress backend URL
        $frontendUrl = $this->config->getFrontendUrl();
        $base = apply_filters('cheapalarms_portal_base_url', trailingslashit($frontendUrl) . 'portal');
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

        // Portal meta is the source of truth for acceptance
        // Check portal meta FIRST (customer accepted in portal)
        $portalMetaStatus = $meta['quote']['status'] ?? 'sent';
        $isAcceptedInPortal = $portalMetaStatus === 'accepted';
        $isRejectedInPortal = $portalMetaStatus === 'rejected';
        
        // Only check GHL status if portal meta doesn't have acceptance
        // (for cases where estimate was accepted directly in GHL)
        $estimateStatus = $estimate['status'] ?? '';
        $isAcceptedInGhl = $estimateStatus === 'accepted';
        
        // Portal meta takes precedence - if accepted in portal, it's accepted
        $isAccepted = $isAcceptedInPortal || $isAcceptedInGhl;

        $quoteStatus = [
            'status'      => $isAccepted ? 'accepted' : ($isRejectedInPortal ? 'rejected' : 'sent'),
            'statusLabel' => $isAcceptedInPortal 
                ? 'Accepted' 
                : ($isAcceptedInGhl ? 'Accepted via GHL' : ($isRejectedInPortal ? 'Rejected' : 'Sent')),
            'number'      => $estimate['estimateNumber'] ?? $estimate['estimateId'],
            'acceptedAt'  => $meta['quote']['acceptedAt'] ?? null,
            'canAccept'   => !$isAccepted && !$isRejectedInPortal, // Can't accept if already accepted or rejected
        ];
        
        // If accepted in portal but no acceptedAt timestamp, set it
        if ($isAcceptedInPortal && empty($quoteStatus['acceptedAt'])) {
            $quoteStatus['acceptedAt'] = current_time('mysql');
        }
        // If accepted in GHL but not in portal meta, update portal meta
        elseif ($isAcceptedInGhl && !$isAcceptedInPortal) {
            $quoteStatus['acceptedAt'] = current_time('mysql');
        }

        // Track if we made any meta updates to avoid unnecessary getMeta() calls
        $metaUpdated = false;
        
        // Only update meta if status changed or if we need to sync acceptedAt
        if ($portalMetaStatus !== $quoteStatus['status'] || 
            ($isAccepted && empty($meta['quote']['acceptedAt']))) {
            $this->updateMeta($estimateId, ['quote' => $quoteStatus]);
            $meta['quote'] = $quoteStatus; // Update local copy instead of fetching
            $metaUpdated = true;
        }

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
                // Only fetch meta if provisionAccount actually updated something
                $meta = $this->getMeta($estimateId);
                $accountMeta = array_merge($defaultAccount, $meta['account'] ?? []);
                $metaUpdated = true;
            } else {
                $this->logger->error('Failed to auto-provision portal account', [
                    'estimateId' => $estimateId,
                    'error'      => $provisioned->get_error_message(),
                ]);
            }
        } elseif ($isAccepted && ($accountMeta['status'] ?? '') === 'active' && !empty($accountMeta['userId'])) {
            $this->attachEstimateToUser((int) $accountMeta['userId'], $estimateId, $locationId);
        }

        // Only refresh meta if we made updates or need latest invoice data
        // Most of the time, we can use the cached $meta we already have
        if ($metaUpdated) {
            $meta = $this->getMeta($estimateId);
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
        // Check if already accepted - prevent duplicate acceptance
        $meta = $this->getMeta($estimateId);
        $currentStatus = $meta['quote']['status'] ?? 'sent';
        
        if ($currentStatus === 'accepted') {
            // Already accepted - return existing status
            $this->logger->info('Estimate already accepted', [
                'estimateId' => $estimateId,
                'acceptedAt' => $meta['quote']['acceptedAt'] ?? null,
            ]);
            return [
                'ok'        => true,
                'quote'     => $meta['quote'],
                'alreadyAccepted' => true,
                'ghlSynced' => false,
                'ghlError'  => null,
            ];
        }
        
        // Check if rejected - cannot accept a rejected estimate
        if ($currentStatus === 'rejected') {
            $this->logger->warning('Attempt to accept rejected estimate', [
                'estimateId' => $estimateId,
                'rejectedAt' => $meta['quote']['rejectedAt'] ?? null,
            ]);
            return new WP_Error(
                'already_rejected',
                __('This estimate has been rejected and cannot be accepted. Please contact support if you need to change this.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Use WordPress transient for race condition protection (5 second lock)
        $lockKey = 'ca_accept_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 5 seconds - previous process likely crashed)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 5) {
                // Lock is stale - clear it and proceed
                delete_transient($lockKey);
                $this->logger->warning('Cleared stale acceptance lock', [
                    'estimateId' => $estimateId,
                    'lockAge' => $lockAge,
                ]);
            } else {
                // Lock is active - another request is processing
                $meta = $this->getMeta($estimateId);
                $currentStatus = $meta['quote']['status'] ?? 'sent';
                if ($currentStatus === 'accepted') {
                    return [
                        'ok'        => true,
                        'quote'     => $meta['quote'],
                        'alreadyAccepted' => true,
                        'ghlSynced' => false,
                        'ghlError'  => null,
                    ];
                }
                // If not accepted yet, return error to prevent duplicate processing
                return new WP_Error(
                    'processing',
                    __('Another request is currently processing this estimate. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                );
            }
        }
        
        // Set lock with timestamp
        set_transient($lockKey, time(), 5);

        try {
            $status = [
                'status'      => 'accepted',
                'statusLabel' => 'Accepted',
                'acceptedAt'  => current_time('mysql'),
                'canAccept'   => false,
            ];

            // Update WordPress meta first (always succeeds)
            $updateResult = $this->updateMeta($estimateId, ['quote' => $status]);
            if (!$updateResult) {
                $this->logger->error('Failed to update portal meta on acceptance', [
                    'estimateId' => $estimateId,
                ]);
                delete_transient($lockKey);
                return new WP_Error(
                    'update_failed',
                    __('Failed to save acceptance status. Please refresh the page and try again. If the problem persists, contact support.', 'cheapalarms'),
                    ['status' => 500]
                );
            }

        // Get locationId from meta if not provided (locationId should be stored in meta from getStatus)
        if (empty($locationId)) {
            $meta = $this->getMeta($estimateId);
            $locationId = $meta['locationId'] ?? '';
        }

        // Validate contact exists before proceeding (for invoice creation)
        // This is a best-effort check - invoice creation will validate again
        if ($locationId) {
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);
            
            if (!is_wp_error($estimate)) {
                $contactId = $estimate['contact']['id'] ?? null;
                if (empty($contactId)) {
                    $this->logger->warning('Estimate accepted but missing contact ID - invoice creation may fail', [
                        'estimateId' => $estimateId,
                        'locationId' => $locationId,
                        'contact' => $estimate['contact'] ?? null,
                    ]);
                    // Don't fail acceptance, but log warning
                } else {
                    $this->logger->info('Estimate accepted with valid contact', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                    ]);
                }
            } else {
                $this->logger->error('Failed to fetch estimate for contact validation', [
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                    'error' => $estimate->get_error_message(),
                ]);
            }
        } else {
            $this->logger->warning('Estimate accepted without locationId - some features may not work', [
                'estimateId' => $estimateId,
            ]);
        }

        // Update GHL signals (non-blocking - errors don't fail acceptance)
        if ($locationId) {
            $this->updateGhlSignals($estimateId, $locationId);
        }
        
        // Auto-provision account if needed (moved from getStatus for immediate provisioning)
        $meta = $this->getMeta($estimateId);
        $accountMeta = $meta['account'] ?? [];
        if (($accountMeta['status'] ?? '') !== 'active') {
            if ($locationId) {
                $estimate = $this->estimateService->getEstimate([
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                
                if (!is_wp_error($estimate)) {
                    $provisioned = $this->provisionAccount($estimateId, $estimate['contact'] ?? [], $locationId);
                    if (!is_wp_error($provisioned)) {
                        $meta = $this->getMeta($estimateId);
                        $accountMeta = $meta['account'] ?? [];
                        $this->logger->info('Account provisioned on estimate acceptance', [
                            'estimateId' => $estimateId,
                            'userId' => $accountMeta['userId'] ?? null,
                        ]);
                    } else {
                        $this->logger->error('Failed to provision account on acceptance', [
                            'estimateId' => $estimateId,
                            'error' => $provisioned->get_error_message(),
                        ]);
                    }
                }
            }
        } elseif (($accountMeta['status'] ?? '') === 'active' && !empty($accountMeta['userId'])) {
            $this->attachEstimateToUser((int) $accountMeta['userId'], $estimateId, $locationId);
        }

            $this->logger->info('Estimate accepted successfully', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'acceptedAt' => $status['acceptedAt'],
            ]);

            // Send acceptance confirmation email (non-blocking - doesn't fail if email fails)
            if ($locationId) {
                $this->sendAcceptanceConfirmationEmail($estimateId, $locationId);
            }

            return [
                'ok'        => true,
                'quote'     => $status,
                'ghlSynced' => false,
                'ghlError'  => null,
            ];
        } finally {
            // Always release lock at the end, even if there's an error
            delete_transient($lockKey);
        }
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
        // Check current status - prevent invalid transitions
        $meta = $this->getMeta($estimateId);
        $currentStatus = $meta['quote']['status'] ?? 'sent';
        
        // Cannot reject if already accepted
        if ($currentStatus === 'accepted') {
            $this->logger->warning('Attempt to reject accepted estimate', [
                'estimateId' => $estimateId,
                'acceptedAt' => $meta['quote']['acceptedAt'] ?? null,
            ]);
            return new WP_Error(
                'already_accepted',
                __('This estimate has already been accepted and cannot be rejected. Please contact support if you need to change this.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Already rejected - return existing status
        if ($currentStatus === 'rejected') {
            $this->logger->info('Estimate already rejected', [
                'estimateId' => $estimateId,
                'rejectedAt' => $meta['quote']['rejectedAt'] ?? null,
            ]);
            return [
                'ok'        => true,
                'quote'     => $meta['quote'],
                'alreadyRejected' => true,
                'ghlSynced' => false,
                'ghlError'  => null,
            ];
        }

        // Use WordPress transient for race condition protection (5 second lock)
        $lockKey = 'ca_reject_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 5 seconds - previous process likely crashed)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 5) {
                // Lock is stale - clear it and proceed
                delete_transient($lockKey);
                $this->logger->warning('Cleared stale rejection lock', [
                    'estimateId' => $estimateId,
                    'lockAge' => $lockAge,
                ]);
            } else {
                // Lock is active - another request is processing
                $meta = $this->getMeta($estimateId);
                $currentStatus = $meta['quote']['status'] ?? 'sent';
                if ($currentStatus === 'rejected') {
                    return [
                        'ok'        => true,
                        'quote'     => $meta['quote'],
                        'alreadyRejected' => true,
                        'ghlSynced' => false,
                        'ghlError'  => null,
                    ];
                }
                // If not rejected yet, return error to prevent duplicate processing
                return new WP_Error(
                    'processing',
                    __('Another request is currently processing this estimate. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                );
            }
        }
        
        // Set lock with timestamp
        set_transient($lockKey, time(), 5);

        try {
            $status = [
                'status'         => 'rejected',
                'statusLabel'    => 'Rejected',
                'rejectedAt'     => current_time('mysql'),
                'rejectionReason' => sanitize_text_field($reason),
                'canAccept'      => false,
            ];

            // Update WordPress meta first
            $updateResult = $this->updateMeta($estimateId, ['quote' => $status]);
            if (!$updateResult) {
                $this->logger->error('Failed to update portal meta on rejection', [
                    'estimateId' => $estimateId,
                ]);
                delete_transient($lockKey);
                return new WP_Error(
                    'update_failed',
                    __('Failed to save rejection status. Please refresh the page and try again. If the problem persists, contact support.', 'cheapalarms'),
                    ['status' => 500]
                );
            }

        // Get locationId from meta if not provided
        if (empty($locationId)) {
            $meta = $this->getMeta($estimateId);
            $locationId = $meta['locationId'] ?? '';
        }

            $this->logger->info('Estimate rejected', [
                'estimateId' => $estimateId,
                'locationId' => $locationId,
                'reason' => $reason ? 'provided' : 'not provided',
            ]);

            return [
                'ok'        => true,
                'quote'     => $status,
                'ghlSynced' => false,
                'ghlError'  => null,
            ];
        } finally {
            // Always release lock at the end, even if there's an error
            delete_transient($lockKey);
        }
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
        // Use WordPress transient for race condition protection (10 second lock)
        $lockKey = 'ca_invoice_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 10 seconds - previous process likely crashed)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 10) {
                // Lock is stale - clear it and proceed
                delete_transient($lockKey);
                $this->logger->warning('Cleared stale invoice creation lock', [
                    'estimateId' => $estimateId,
                    'lockAge' => $lockAge,
                ]);
            } else {
                // Lock is active - another request is processing
                // Check if invoice was already created
                $meta = $this->getMeta($estimateId);
                if (!empty($meta['invoice']['id'])) {
                    return [
                        'invoice' => $meta['invoice'],
                        'exists'  => true,
                    ];
                }
                // If not created yet, return error to prevent duplicate processing
                return new WP_Error(
                    'processing',
                    __('Another request is currently creating an invoice for this estimate. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                );
            }
        }

        // Set lock with timestamp
        set_transient($lockKey, time(), 10);

        try {
            $meta  = $this->getMeta($estimateId);
            $force = !empty($options['force']);
            unset($options['force']);

            if (!$force && !empty($meta['invoice']['id'])) {
                delete_transient($lockKey);
                return [
                    'invoice' => $meta['invoice'],
                    'exists'  => true,
                ];
            }

        $resolvedLocation = $locationId ?: ($meta['locationId'] ?? '');
        if (!$resolvedLocation) {
            // Fallback to config default location
            $resolvedLocation = $this->config->getLocationId();
            if (!$resolvedLocation) {
                return new WP_Error('missing_location', __('Location ID required to create invoice.', 'cheapalarms'), ['status' => 400]);
            }
            // Store resolved location in meta for future use
            $this->updateMeta($estimateId, ['locationId' => $resolvedLocation]);
        }

        // Create invoice directly from draft estimate (no need to accept estimate first)
        // Add retry logic for transient GHL errors
        $maxRetries = 2;
        $attempt = 0;
        $response = null;
        
        while ($attempt <= $maxRetries) {
            $response = $this->estimateService->createInvoiceFromDraftEstimate($estimateId, $resolvedLocation, $options);
            
            if (!is_wp_error($response)) {
                // Success - break out of retry loop
                break;
            }
            
            // Check if this is a transient error that might benefit from retry
            $errorCode = $response->get_error_code();
            $errorMessage = $response->get_error_message();
            $errorData = $response->get_error_data();
            $httpCode = $errorData['code'] ?? null;
            
            $isTransientError = (
                strpos($errorMessage, 'SSL') !== false ||
                strpos($errorMessage, 'SSL_ERROR') !== false ||
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 35') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false ||
                $errorCode === 'ghl_connection_error' ||
                $errorCode === 'ghl_ssl_error' ||
                $errorCode === 'ghl_timeout' ||
                ($httpCode && $httpCode >= 500 && $httpCode < 600) // 5xx server errors
            );
            
            // If not a transient error or max retries reached, return error
            if (!$isTransientError || $attempt >= $maxRetries) {
                return $response;
            }
            
            // Wait before retry (exponential backoff: 1s, 2s)
            $waitTime = pow(2, $attempt) * 1000000; // microseconds
            usleep($waitTime);
            $attempt++;
            
            $this->logger->warning('Retrying invoice creation after transient error', [
                'estimateId' => $estimateId,
                'attempt' => $attempt,
                'error' => $errorMessage,
            ]);
        }
        
        if (is_wp_error($response)) {
            return $response;
        }

        $payload = $response['result'] ?? [];
        $invoice = $this->normaliseInvoiceResponse($payload);

        if (!$invoice['id']) {
            // Invoice ID is critical - return error instead of just warning
            $this->logger->error('GHL invoice response missing identifier', [
                'estimateId' => $estimateId,
                'payload'    => $payload,
            ]);
            return new WP_Error(
                'invalid_invoice_response',
                __('Invoice was created in GoHighLevel but the response was missing required information. Please contact support with the estimate number for assistance.', 'cheapalarms'),
                ['status' => 500, 'payload' => $payload]
            );
        }

        $this->updateMeta($estimateId, ['invoice' => $invoice]);

        // Update GHL note with invoice information (non-blocking)
        if (!empty($invoice['id']) && $resolvedLocation) {
            $this->updateGhlNoteWithInvoice($estimateId, $resolvedLocation, $invoice);
        }

        // Send invoice ready email (non-blocking - doesn't fail if email fails)
        if (!empty($invoice['id']) && $resolvedLocation) {
            $this->sendInvoiceReadyEmail($estimateId, $resolvedLocation, $invoice);
        }

        return [
            'invoice' => $invoice,
        ];
        } finally {
            // Always release lock at the end, even if there's an error
            delete_transient($lockKey);
        }
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
     * Submit photos for review
     * Marks photo submission status as "submitted" with timestamp
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @return array|WP_Error
     */
    public function submitPhotos(string $estimateId, string $locationId = '')
    {
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        $meta = $this->getMeta($estimateId);
        
        // Get actual uploaded photos from storage
        $stored = get_option('ca_estimate_uploads_' . $estimateId, '');
        $uploadData = $stored ? json_decode($stored, true) : null;
        $uploads = is_array($uploadData['uploads'] ?? null) ? $uploadData['uploads'] : [];
        
        // Build photos structure with actual data
        $photos = $meta['photos'] ?? [];
        $photos['total'] = count($uploads);
        $photos['uploaded'] = count($uploads);
        $photos['items'] = $uploads;
        $photos['submission_status'] = 'submitted';
        $photos['submitted_at'] = current_time('mysql');
        $photos['last_edited_at'] = current_time('mysql');
        
        // Update meta
        $meta['photos'] = $photos;
        update_option(self::OPTION_PREFIX . $estimateId, wp_json_encode($meta), false);
        
        // Send notification to admin
        $this->sendPhotoSubmissionNotificationToAdmin($estimateId, $locationId, $photos['total']);
        
        return [
            'ok' => true,
            'submission_status' => 'submitted',
            'submitted_at' => $photos['submitted_at'],
            'photo_count' => $photos['total'],
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

        // Set ca_customer role (has ca_access_portal capability)
        wp_update_user(['ID' => $userId, 'role' => 'ca_customer']);
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
        $contactId = $contact['id'] ?? null;

        $resetUrl = $this->sendPortalInvite(
            $email,
            $displayName,
            $portalUrl,
            (int) $userId,
            false,
            $contactId,
            $estimateId,
            $locationId
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
        $contactId = $contact['id'] ?? null;

        $resetUrl = $this->sendPortalInvite(
            $email,
            $contactName,
            $portalLink,
            $userId,
            true,
            $contactId,
            $estimateId,
            null // locationId not needed for resend
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
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->warning('Failed to decode portal meta JSON', [
                'estimateId' => $estimateId,
                'error' => json_last_error_msg(),
            ]);
            return [];
        }
        if (!is_array($decoded)) {
            return [];
        }
        return $decoded;
    }

    private function updateMeta(string $estimateId, array $changes): bool
    {
        // Use a lock to prevent race conditions during meta updates
        $lockKey = 'ca_meta_update_lock_' . $estimateId;
        $maxAttempts = 5;
        $attempt = 0;
        
        while ($attempt < $maxAttempts) {
            // Try to acquire lock (1 second timeout)
            $lockValue = get_transient($lockKey);
            if ($lockValue !== false) {
                // Lock exists - wait a bit and retry
                usleep(200000); // 200ms
                $attempt++;
                continue;
            }
            
            // Acquire lock
            set_transient($lockKey, time(), 1);
            
            try {
                // Get current meta (fresh read)
                $current = $this->getMeta($estimateId);
                
                // Deep merge to preserve nested structures
                $merged = $this->deepMerge($current, $changes);
                
                // Update atomically
                $result = update_option(self::OPTION_PREFIX . $estimateId, wp_json_encode($merged), false);
                
                // Release lock
                delete_transient($lockKey);
                
                if (!$result) {
                    $this->logger->warning('Failed to update portal meta', [
                        'estimateId' => $estimateId,
                        'changes' => array_keys($changes),
                    ]);
                }
                return $result;
            } catch (\Exception $e) {
                // Release lock on error
                delete_transient($lockKey);
                $this->logger->error('Exception updating portal meta', [
                    'estimateId' => $estimateId,
                    'error' => $e->getMessage(),
                ]);
                return false;
            }
        }
        
        // Failed to acquire lock after max attempts
        $this->logger->warning('Failed to acquire meta update lock after max attempts', [
            'estimateId' => $estimateId,
            'attempts' => $maxAttempts,
        ]);
        return false;
    }

    /**
     * Deep merge arrays, preserving nested structures.
     * 
     * @param array<string, mixed> $current
     * @param array<string, mixed> $changes
     * @return array<string, mixed>
     */
    private function deepMerge(array $current, array $changes): array
    {
        foreach ($changes as $key => $value) {
            if (isset($current[$key]) && is_array($current[$key]) && is_array($value)) {
                // Recursively merge nested arrays
                $current[$key] = $this->deepMerge($current[$key], $value);
            } else {
                // Overwrite or add new value
                $current[$key] = $value;
            }
        }
        return $current;
    }

    public function validateInviteToken(string $estimateId, string $token): bool
    {
        if (!$estimateId || !$token) {
            return false;
        }

        $accountToken = $this->getMeta($estimateId)['account']['inviteToken'] ?? null;

        return is_string($accountToken) && hash_equals($accountToken, $token);
    }

    private function sendPortalInvite(string $email, string $name, string $portalUrl, int $userId, bool $isResend, ?string $contactId = null, ?string $estimateId = null, ?string $locationId = null): ?string
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

        // Generate password reset key pointing to Next.js frontend
        $key = get_password_reset_key($user);
        $resetUrl = null;
        if (!is_wp_error($key)) {
            $frontendUrl = $this->config->getFrontendUrl();
            $resetUrl = add_query_arg(
                [
                    'key' => $key,
                    'login' => rawurlencode($user->user_login),
                    'estimateId' => $estimateId ?: '',
                ],
                trailingslashit($frontendUrl) . 'set-password'
            );
        }

        $headers  = ['Content-Type: text/html; charset=UTF-8'];
        $greeting = sprintf(__('Hi %s,', 'cheapalarms'), $name);

        $body  = '<p>' . esc_html($greeting) . '</p>';
        $body .= '<p>' . esc_html(__('We have prepared your CheapAlarms portal. Use the secure links below to access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
        $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';
        
        if ($resetUrl) {
            $body .= '<p><a href="' . esc_url($resetUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('Set your password', 'cheapalarms')) . '</a></p>';
        }
        
        $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
        $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';

        // Send via GHL if contactId available (all customer emails must use GHL)
        $sent = false;
        if ($contactId) {
            $sent = $this->sendEmailViaGhl($contactId, $subject, $body);
        } else {
            // Fallback: Try to get contactId from estimate
            if ($estimateId && $locationId) {
                $estimate = $this->estimateService->getEstimate([
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                if (!is_wp_error($estimate)) {
                    $contactId = $estimate['contact']['id'] ?? null;
                    if ($contactId) {
                        $sent = $this->sendEmailViaGhl($contactId, $subject, $body);
                    }
                }
            }
            
            // No wp_mail fallback - all customer emails must use GHL
            // If no contactId, log error but don't send via wp_mail
            if (!$sent && !$contactId) {
                $this->logger->error('Cannot send portal invite: No GHL contactId available', [
                    'email' => $email,
                    'userId' => $userId,
                    'estimateId' => $estimateId,
                ]);
            }
        }

        $this->logger->info('Portal invite email sent', [
            'email'     => $email,
            'userId'    => $userId,
            'resend'    => $isResend,
            'contactId' => $contactId,
            'sentViaGhl' => $contactId ? true : false,
            'sent'      => $sent,
        ]);

        return $resetUrl;
    }

    /**
     * Send email via GHL Conversations API
     * @param string $contactId GHL contact ID
     * @param string $subject Email subject
     * @param string $htmlBody Email HTML body
     * @return bool Success status
     */
    private function sendEmailViaGhl(string $contactId, string $subject, string $htmlBody): bool
    {
        try {
            if (empty($contactId)) {
                $this->logger->warning('Cannot send GHL email without contactId');
                return false;
            }

            $ghlClient = $this->container->get(GhlClient::class);
            $fromEmail = get_option('ghl_from_email', 'quotes@cheapalarms.com.au');
            
            $payload = [
                'contactId' => $contactId,
                'type' => 'Email',
                'status' => 'pending',
                'subject' => $subject,
                'html' => $htmlBody,
                'emailFrom' => $fromEmail,
            ];
            
            if ($this->config->getLocationId()) {
                $payload['locationId'] = $this->config->getLocationId();
            }
            
            $result = $ghlClient->post('/conversations/messages', $payload);
            
            if (is_wp_error($result)) {
                $this->logger->error('GHL email API failed', [
                    'contactId' => $contactId,
                    'subject' => $subject,
                    'error' => $result->get_error_message(),
                ]);
                return false;
            }
            
            $this->logger->info('Email sent via GHL', [
                'contactId' => $contactId,
                'subject' => $subject,
            ]);
            
            return true;
        } catch (\Exception $e) {
            $this->logger->error('Exception sending GHL email', [
                'contactId' => $contactId,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Send invoice ready email to customer
     * @param string $estimateId
     * @param string $locationId
     * @param array $invoice
     * @return void
     */
    private function sendInvoiceReadyEmail(string $estimateId, string $locationId, array $invoice): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for invoice email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for invoice notification', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $invoiceNumber = sanitize_text_field($invoice['invoiceNumber'] ?? $invoice['id']);
            $invoiceUrl = $invoice['url'] ?? '';
            $invoiceTotal = $invoice['total'] ?? 0;
            $currency = $invoice['currency'] ?? 'AUD';
            $dueDate = $invoice['dueDate'] ?? '';
            $portalUrl = $this->resolvePortalUrl($estimateId);

            if (empty($invoiceUrl)) {
                $this->logger->warning('Invoice URL missing for email notification', [
                    'estimateId' => $estimateId,
                    'invoiceId' => $invoice['id'] ?? null,
                ]);
                return;
            }

            $subject = __('Your invoice is ready for payment', 'cheapalarms');
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
            $body .= '<p>' . esc_html(__('Great news! Your invoice is now ready for payment.', 'cheapalarms')) . '</p>';
            
            $body .= '<p><strong>' . esc_html(sprintf(__('Invoice #%s', 'cheapalarms'), $invoiceNumber)) . '</strong><br />';
            $body .= esc_html(sprintf(__('Amount: %s $%s', 'cheapalarms'), $currency, number_format($invoiceTotal, 2))) . '</p>';
            
            if ($dueDate) {
                $formattedDate = date_i18n(get_option('date_format'), strtotime($dueDate));
                $body .= '<p>' . esc_html(sprintf(__('Due Date: %s', 'cheapalarms'), $formattedDate)) . '</p>';
            }

            $body .= '<p><a href="' . esc_url($invoiceUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('View & Pay Invoice', 'cheapalarms')) . '</a></p>';

            $body .= '<p>' . esc_html(__('Payment Options:', 'cheapalarms')) . '</p>';
            $body .= '<ul>';
            $body .= '<li>' . esc_html(__('Click the button above to pay online securely', 'cheapalarms')) . '</li>';
            $body .= '<li>' . esc_html(__('Multiple payment methods accepted', 'cheapalarms')) . '</li>';
            $body .= '</ul>';

            $body .= '<p>' . esc_html(__('You can also view this invoice and track your project progress in your portal:', 'cheapalarms')) . '</p>';
            $body .= '<p><a href="' . esc_url($portalUrl) . '">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';

            $body .= '<p>' . esc_html(__('If you have any questions about your invoice, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
            $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';

            // Send via GHL instead of wp_mail
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $sent = $this->sendEmailViaGhl($contactId, $subject, $body);
            } else {
                $this->logger->warning('No GHL contact ID for invoice email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $this->logger->info('Invoice ready email sent via GHL', [
                'estimateId' => $estimateId,
                'invoiceId' => $invoice['id'] ?? null,
                'contactId' => $contactId,
                'sent' => $sent,
            ]);
        } catch (\Exception $e) {
            // Don't fail invoice creation if email fails
            $this->logger->error('Failed to send invoice ready email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send acceptance confirmation email to customer
     * @param string $estimateId
     * @param string $locationId
     * @return void
     */
    private function sendAcceptanceConfirmationEmail(string $estimateId, string $locationId): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for acceptance email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for acceptance confirmation', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);
            
            // Get invoice URL if available
            $meta = $this->getMeta($estimateId);
            $invoice = $meta['invoice'] ?? null;
            $invoiceUrl = $invoice['url'] ?? null;

            $subject = __('Thank you for accepting your estimate', 'cheapalarms');
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
            $body .= '<p>' . esc_html(sprintf(
                __('Thank you for accepting estimate #%s! We\'re excited to move forward with your project.', 'cheapalarms'),
                $estimateNumber
            )) . '</p>';

            if ($invoiceUrl) {
                $body .= '<p>' . esc_html(__('Your invoice has been created and is ready for payment:', 'cheapalarms')) . '</p>';
                $body .= '<p><a href="' . esc_url($invoiceUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('View & Pay Invoice', 'cheapalarms')) . '</a></p>';
            } else {
                $body .= '<p>' . esc_html(__('We\'re preparing your invoice and will send it to you shortly.', 'cheapalarms')) . '</p>';
            }

            $body .= '<p>' . esc_html(__('You can view your estimate and track progress in your portal:', 'cheapalarms')) . '</p>';
            $body .= '<p><a href="' . esc_url($portalUrl) . '">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';
            
            $body .= '<p>' . esc_html(__('Next Steps:', 'cheapalarms')) . '</p>';
            $body .= '<ul>';
            $body .= '<li>' . esc_html(__('Complete payment using the invoice link above', 'cheapalarms')) . '</li>';
            $body .= '<li>' . esc_html(__('Upload any required photos through your portal', 'cheapalarms')) . '</li>';
            $body .= '<li>' . esc_html(__('Our team will contact you to schedule installation', 'cheapalarms')) . '</li>';
            $body .= '</ul>';

            $body .= '<p>' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
            $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';

            // Send via GHL instead of wp_mail
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $sent = $this->sendEmailViaGhl($contactId, $subject, $body);
            } else {
                $this->logger->warning('No GHL contact ID for acceptance email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $this->logger->info('Acceptance confirmation email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'hasInvoice' => !empty($invoiceUrl),
            ]);
        } catch (\Exception $e) {
            // Don't fail acceptance if email fails
            $this->logger->error('Failed to send acceptance confirmation email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
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

    /**
     * Send notification to admin when customer submits photos
     * @param string $estimateId
     * @param string $locationId
     * @param int $photoCount
     * @return void
     */
    private function sendPhotoSubmissionNotificationToAdmin(string $estimateId, string $locationId, int $photoCount): void
    {
        try {
            // Get estimate to fetch customer details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for admin photo notification', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            // Get admin email
            $adminEmail = get_option('admin_email');
            if (empty($adminEmail)) {
                $this->logger->warning('No admin email configured for photo submission notification', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            
            // Admin dashboard URL (pointing to Next.js frontend)
            $adminUrl = $this->config->getFrontendUrl() . '/admin/estimates?id=' . $estimateId;

            $subject = sprintf('[CheapAlarms] Customer submitted %d photos for Estimate #%s', $photoCount, $estimateNumber);
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $body = '<h2>📸 Customer Photos Submitted</h2>';
            $body .= '<p><strong>Customer:</strong> ' . esc_html($customerName) . '</p>';
            $body .= '<p><strong>Estimate:</strong> #' . esc_html($estimateNumber) . '</p>';
            $body .= '<p><strong>Photos uploaded:</strong> ' . $photoCount . '</p>';
            $body .= '<p><strong>Submitted:</strong> ' . current_time('F j, Y g:i A') . '</p>';
            $body .= '<hr>';
            $body .= '<p>The customer has finished uploading installation photos. Please review them and proceed with the next steps:</p>';
            $body .= '<ol>';
            $body .= '<li>Review all uploaded photos in the admin panel</li>';
            $body .= '<li>Verify pricing is accurate (adjust estimate if needed)</li>';
            $body .= '<li>Create the invoice for the customer</li>';
            $body .= '</ol>';
            $body .= '<p><a href="' . esc_url($adminUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #1EA6DF; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">View Estimate in Admin Panel</a></p>';
            $body .= '<hr>';
            $body .= '<p style="color: #666; font-size: 12px;">This is an automated notification from CheapAlarms Customer Portal.</p>';

            $sent = wp_mail($adminEmail, $subject, $body, $headers);

            if ($sent) {
                $this->logger->info('Admin photo submission notification sent', [
                    'estimateId' => $estimateId,
                    'photoCount' => $photoCount,
                    'adminEmail' => $adminEmail,
                ]);
            } else {
                $this->logger->warning('Failed to send admin photo submission notification', [
                    'estimateId' => $estimateId,
                    'adminEmail' => $adminEmail,
                ]);
            }

        } catch (\Exception $e) {
            // Don't fail photo submission if email fails
            $this->logger->error('Exception sending admin photo notification', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Store estimate revision data in portal meta
     * Used when admin edits estimate based on customer photos
     * 
     * @param string $estimateId
     * @param array $revisionData
     * @return bool
     */
    public function storeRevisionData(string $estimateId, array $revisionData): bool
    {
        try {
            $this->logger->info('Storing estimate revision data', [
                'estimateId' => $estimateId,
                'netChange' => $revisionData['netChange'] ?? 0,
                'hasNote' => !empty($revisionData['adminNote']),
            ]);

            return $this->updateMeta($estimateId, ['revision' => $revisionData]);
        } catch (\Exception $e) {
            $this->logger->error('Failed to store revision data', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Send estimate revision notification to customer
     * Highlights savings or changes based on photo review
     * 
     * @param string $estimateId
     * @param string $locationId
     * @param array $revisionData
     * @return void
     */
    public function sendRevisionNotification(string $estimateId, string $locationId, array $revisionData): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for revision email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for revision notification', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);
            
            $oldTotal = floatval($revisionData['oldTotal'] ?? 0);
            $newTotal = floatval($revisionData['newTotal'] ?? 0);
            $netChange = floatval($revisionData['netChange'] ?? 0);
            $currency = $estimate['currency'] ?? 'AUD';
            $adminNote = sanitize_text_field($revisionData['adminNote'] ?? '');
            
            $isSavings = $netChange < 0;
            $isIncrease = $netChange > 0;

            // Different subject lines for savings vs increases
            $subject = $isSavings 
                ? sprintf(__('🎉 Great news! Your CheapAlarms estimate has been updated - Save %s %s', 'cheapalarms'), $currency, number_format(abs($netChange), 2))
                : __('Your CheapAlarms estimate has been updated', 'cheapalarms');

            $body = '<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">';
            
            $body .= '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';

            if ($isSavings) {
                $body .= '<p><strong style="color: #10b981; font-size: 18px;">Good news!</strong> We\'ve reviewed the installation photos you submitted and found opportunities to optimize your installation.</p>';
            } else {
                $body .= '<p>We\'ve carefully reviewed the installation photos you submitted and updated your estimate to ensure accurate pricing for your specific site.</p>';
            }

            // Pricing box
            $boxColor = $isSavings ? '#10b981' : '#1EA6DF';
            $body .= '<div style="background: linear-gradient(135deg, ' . $boxColor . ', ' . ($isSavings ? '#059669' : '#0e7490') . '); color: white; padding: 24px; border-radius: 16px; margin: 24px 0; text-align: center;">';
            $body .= '<div style="font-size: 14px; opacity: 0.9; margin-bottom: 8px;">YOUR UPDATED PRICING</div>';
            $body .= '<div style="font-size: 24px; text-decoration: line-through; opacity: 0.7; margin-bottom: 8px;">' . esc_html($currency . ' ' . number_format($oldTotal, 2)) . '</div>';
            $body .= '<div style="font-size: 36px; font-weight: bold; margin-bottom: 16px;">' . esc_html($currency . ' ' . number_format($newTotal, 2)) . '</div>';
            
            if ($netChange !== 0) {
                if ($isSavings) {
                    $body .= '<div style="font-size: 28px; font-weight: bold; background: rgba(255,255,255,0.2); padding: 12px 24px; border-radius: 12px; display: inline-block;">🎊 YOU SAVE ' . esc_html($currency . ' ' . number_format(abs($netChange), 2)) . '</div>';
                } else {
                    $body .= '<div style="font-size: 18px; background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; display: inline-block;">Additional: +' . esc_html($currency . ' ' . number_format(abs($netChange), 2)) . '</div>';
                }
            }
            $body .= '</div>';

            // Admin note
            if ($adminNote) {
                $body .= '<div style="background: #f8f9fa; border-left: 4px solid ' . $boxColor . '; padding: 16px; border-radius: 8px; margin: 24px 0;">';
                $body .= '<div style="font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 8px;">FROM YOUR INSTALLER</div>';
                $body .= '<div style="color: #1f2937;">' . nl2br(esc_html($adminNote)) . '</div>';
                $body .= '</div>';
            }

            // Call to action
            $body .= '<p><strong>What\'s next:</strong></p>';
            $body .= '<ol>';
            $body .= '<li>Review the updated estimate in your portal</li>';
            if ($isSavings) {
                $body .= '<li><strong>Accept now to lock in your savings!</strong></li>';
            } else {
                $body .= '<li>If you\'re happy with the pricing, accept the estimate</li>';
            }
            $body .= '<li>We\'ll then create your invoice and schedule installation</li>';
            $body .= '</ol>';

            $body .= '<p style="text-align: center; margin: 32px 0;"><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 16px 32px; background: linear-gradient(135deg, #1EA6DF, #c95375); color: white; text-decoration: none; border-radius: 50px; font-weight: bold; font-size: 16px;">View Updated Estimate</a></p>';

            $body .= '<p style="color: #6b7280; font-size: 14px;">Have questions about the changes? Just reply to this email!</p>';
            $body .= '<p>Thanks,<br/>CheapAlarms Team</p>';
            $body .= '</div>';

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $sent = $this->sendEmailViaGhl($contactId, $subject, $body);
            } else {
                $this->logger->warning('No GHL contact ID for revision email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            if ($sent) {
                $this->logger->info('Estimate revision notification sent', [
                    'estimateId' => $estimateId,
                    'contactId' => $contactId,
                    'isSavings' => $isSavings,
                    'netChange' => $netChange,
                ]);
            }

        } catch (\Exception $e) {
            // Don't fail estimate update if email fails
            $this->logger->error('Failed to send revision notification', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }
}

