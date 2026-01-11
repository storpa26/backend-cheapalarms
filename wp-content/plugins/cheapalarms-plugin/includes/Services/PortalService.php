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
use function get_transient;
use function set_transient;
use function delete_transient;

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

    /**
     * Generate a cryptographically secure invite token
     * SECURITY: Tokens are hashed before storage (see hashInviteToken)
     * 
     * @return string Plaintext token (will be hashed before storage)
     */
    public static function generateToken(): string
    {
        return wp_generate_password(48, false, false);
    }
    
    /**
     * Hash an invite token for secure storage
     * SECURITY: Uses password_hash (bcrypt) to prevent token disclosure if database is compromised
     * 
     * @param string $token Plaintext token
     * @return string Hashed token
     */
    public static function hashInviteToken(string $token): string
    {
        return password_hash($token, PASSWORD_DEFAULT);
    }
    
    /**
     * Verify an invite token against a stored hash
     * SECURITY: Supports both hashed (new) and plaintext (legacy) tokens for backward compatibility
     * 
     * @param string $providedToken Token provided by user
     * @param string $storedToken Stored token (may be hash or plaintext)
     * @return bool True if token matches
     */
    public static function verifyInviteToken(string $providedToken, string $storedToken): bool
    {
        // Check if stored token is a password hash (starts with $2y$, $2a$, etc.)
        if (preg_match('/^\$2[ayb]\$/', $storedToken)) {
            // New format: hashed token - use password_verify
            return password_verify($providedToken, $storedToken);
        }
        
        // Legacy format: plaintext token - use hash_equals for timing-safe comparison
        // After successful verification, we should upgrade to hash (but don't do it here to avoid side effects)
        return hash_equals($storedToken, $providedToken);
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

        if ($inviteToken) {
            $validationResult = $this->validateInviteToken($estimateId, $inviteToken);
            if (!$validationResult['valid']) {
                return new WP_Error(
                    $validationResult['reason'] === 'expired' ? 'expired_invite' : 'invalid_invite',
                    $validationResult['message'] ?? __('The invite link is no longer valid.', 'cheapalarms'),
                    ['status' => 403, 'reason' => $validationResult['reason']]
                );
            }
        }

        // Resolve locationId: request param → meta → config default (CRITICAL: prevents estimate unavailable)
        $effectiveLocation = $locationId ?: ($meta['locationId'] ?? $this->config->getLocationId());

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
            // Only update if locationId changed (prevents false positive warnings)
            if (($meta['locationId'] ?? '') !== $effectiveLocation) {
                $meta['locationId'] = $effectiveLocation;
                $this->updateMeta($estimateId, ['locationId' => $effectiveLocation]);
            } else {
                // Ensure local copy is set even if no update needed
                $meta['locationId'] = $effectiveLocation;
            }
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

        // Check if acceptance is enabled and workflow is ready
        $workflowStatus = $meta['workflow']['status'] ?? null;
        $acceptanceEnabled = !empty($meta['quote']['acceptance_enabled']);
        $isReadyToAccept = $workflowStatus === 'ready_to_accept';
        
        $quoteStatus = [
            'status'      => $isAccepted ? 'accepted' : ($isRejectedInPortal ? 'rejected' : 'sent'),
            'statusLabel' => $isAcceptedInPortal 
                ? 'Accepted' 
                : ($isAcceptedInGhl ? 'Accepted via GHL' : ($isRejectedInPortal ? 'Rejected' : 'Sent')),
            'number'      => $estimate['estimateNumber'] ?? $estimate['estimateId'],
            'acceptedAt'  => $meta['quote']['acceptedAt'] ?? null,
            'canAccept'   => !$isAccepted && !$isRejectedInPortal && $acceptanceEnabled && $isReadyToAccept, // Can only accept when acceptance is enabled and workflow is ready_to_accept
            'approval_requested' => $meta['quote']['approval_requested'] ?? false, // NEW: Include approval_requested flag
            'acceptance_enabled' => $acceptanceEnabled, // Include acceptance_enabled flag
            // NEW: Include revisionNumber and photos_required for frontend
            'revisionNumber' => $meta['quote']['revisionNumber'] ?? null,
            'photos_required' => !empty($meta['quote']['photos_required']),
        ];
        
        // Store estimate snapshot data for fast dashboard loading (no GHL calls needed)
        $quoteStatus['total'] = $estimate['total'] ?? ($meta['quote']['total'] ?? null);
        $quoteStatus['currency'] = $estimate['currency'] ?? ($meta['quote']['currency'] ?? 'AUD');
        $quoteStatus['last_synced_at'] = current_time('mysql');
        
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
        
        // Update meta if status changed, acceptedAt changed, or estimate data is missing/stale
        $needsUpdate = false;
        $needsUpdate = $needsUpdate || ($portalMetaStatus !== $quoteStatus['status']);
        $needsUpdate = $needsUpdate || ($isAccepted && empty($meta['quote']['acceptedAt']));
        $needsUpdate = $needsUpdate || empty($meta['quote']['number']); // Store number if missing
        $needsUpdate = $needsUpdate || empty($meta['quote']['total']); // Store total if missing
        $needsUpdate = $needsUpdate || ($meta['quote']['number'] ?? null) !== $quoteStatus['number']; // Update if number changed
        
        if ($needsUpdate) {
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

        // Calculate guest mode info
        $isGuestMode = ($inviteToken && !$user);
        $daysRemaining = null;
        if ($isGuestMode && !empty($accountMeta['expiresAt'])) {
            $expiryTimestamp = strtotime($accountMeta['expiresAt']);
            if ($expiryTimestamp) {
                $secondsRemaining = $expiryTimestamp - time();
                $daysRemaining = max(0, ceil($secondsRemaining / DAY_IN_SECONDS));
            }
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
            'workflow'     => $meta['workflow'] ?? null, // Include workflow data for customer portal
            'booking'     => $meta['booking'] ?? null, // Include booking data for customer portal
            'payment'     => $meta['payment'] ?? null, // Include payment data for customer portal
            'revision'     => $meta['revision'] ?? null, // Include revision data for customer portal
            'isGuestMode'  => $isGuestMode,
            'daysRemaining' => $daysRemaining,
            'canCreateAccount' => $isGuestMode, // Guests can always create account
            'canBook' => $this->canBook($estimateId), // Check if booking is available
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

        // Check if acceptance is enabled (CRITICAL: Customer can only accept when admin enables it)
        $workflow = $meta['workflow'] ?? [];
        $quote = $meta['quote'] ?? [];
        
        if (empty($quote['acceptance_enabled']) || ($workflow['status'] ?? null) !== 'ready_to_accept') {
            $this->logger->warning('Attempt to accept estimate before acceptance enabled', [
                'estimateId' => $estimateId,
                'acceptance_enabled' => $quote['acceptance_enabled'] ?? false,
                'workflow_status' => $workflow['status'] ?? null,
            ]);
            return new WP_Error(
                'acceptance_not_enabled',
                __('Acceptance is not yet enabled for this estimate. Please wait for admin review.', 'cheapalarms'),
                ['status' => 403]
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
                'approval_requested' => false, // Reset after acceptance
                'acceptance_enabled' => false, // Reset after acceptance
            ];

            // Initialize or update workflow status to "accepted"
            $meta = $this->getMeta($estimateId);
            $workflow = $meta['workflow'] ?? [];
            
            // Initialize workflow if it doesn't exist
            if (empty($workflow) || !isset($workflow['status'])) {
                $workflow = [
                    'status' => 'accepted',
                    'currentStep' => 3,
                    'requestedAt' => $meta['quote']['createdAt'] ?? current_time('mysql'),
                    'acceptedAt' => current_time('mysql'),
                ];
            } else {
                // Update existing workflow
                $workflow['status'] = 'accepted';
                $workflow['currentStep'] = 3;
                $workflow['acceptedAt'] = current_time('mysql');
                
                // Preserve existing timestamps
                if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
                    $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
                }
                if (!isset($workflow['reviewedAt']) && isset($meta['workflow']['reviewedAt'])) {
                    $workflow['reviewedAt'] = $meta['workflow']['reviewedAt'];
                }
            }

            // Update WordPress meta first (always succeeds)
            $updateResult = $this->updateMeta($estimateId, [
                'quote' => $status,
                'workflow' => $workflow,
            ]);
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
            // Get workflow to update it
            $workflow = $meta['workflow'] ?? [];
            $workflow['status'] = 'rejected';
            $workflow['rejectedAt'] = current_time('mysql');
            
            $status = [
                'status'         => 'rejected',
                'statusLabel'    => 'Rejected',
                'rejectedAt'     => current_time('mysql'),
                'rejectionReason' => sanitize_text_field($reason),
                'canAccept'      => false,
                'approval_requested' => false, // Reset approval request
                'acceptance_enabled' => false, // Reset acceptance enabled
            ];

            // Update WordPress meta first
            $updateResult = $this->updateMeta($estimateId, [
                'quote' => $status,
                'workflow' => $workflow,
            ]);
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
     * Request review after uploading photos (or immediately if no photos required)
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @return array|WP_Error
     */
    public function requestReview(string $estimateId, string $locationId = '')
    {
        $meta = $this->getMeta($estimateId);
        $workflow = $meta['workflow'] ?? [];
        $quote = $meta['quote'] ?? [];
        $photos = $meta['photos'] ?? [];
        
        // Validate workflow status
        if (($workflow['status'] ?? null) !== 'sent') {
            return new WP_Error(
                'invalid_status',
                __('Can only request review when estimate is sent.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Validate not already requested
        if (!empty($quote['approval_requested'])) {
            return new WP_Error(
                'already_requested',
                __('Review has already been requested.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Validate not already accepted/rejected
        if (($quote['status'] ?? 'sent') === 'accepted') {
            return new WP_Error(
                'already_accepted',
                __('Estimate has already been accepted.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        if (($quote['status'] ?? 'sent') === 'rejected') {
            return new WP_Error(
                'already_rejected',
                __('Estimate has been rejected.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // If photos required, validate photos uploaded
        if (!empty($quote['photos_required'])) {
            $uploadedCount = $photos['uploaded'] ?? 0;
            if ($uploadedCount === 0) {
                return new WP_Error(
                    'photos_required',
                    __('Please upload photos before requesting review.', 'cheapalarms'),
                    ['status' => 400]
                );
            }
            
            // Auto-submit photos if not already submitted
            if (($photos['submission_status'] ?? null) !== 'submitted') {
                $photos['submission_status'] = 'submitted';
                $photos['submitted_at'] = current_time('mysql');
            }
        }
        
        // Update meta
        $updateResult = $this->updateMeta($estimateId, [
            'quote' => array_merge($quote, [
                'approval_requested' => true,
            ]),
            'workflow' => array_merge($workflow, [
                'status' => 'under_review',
                'currentStep' => 2,
            ]),
            'photos' => $photos, // Include updated photos if auto-submitted
        ]);
        
        if (!$updateResult) {
            $this->logger->error('Failed to update portal meta on review request', [
                'estimateId' => $estimateId,
            ]);
            return new WP_Error(
                'update_failed',
                __('Failed to save review request. Please refresh the page and try again.', 'cheapalarms'),
                ['status' => 500]
            );
        }
        
        // Send notification to admin
        $this->sendReviewRequestNotificationToAdmin($estimateId, $locationId, $quote, $photos);
        
        $this->logger->info('Review requested', [
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'photosRequired' => !empty($quote['photos_required']),
            'photosUploaded' => $photos['uploaded'] ?? 0,
        ]);
        
        return [
            'ok' => true,
            'message' => __('Review request submitted successfully. Admin will review and notify you when acceptance is enabled.', 'cheapalarms'),
            'workflow' => [
                'status' => 'under_review',
                'currentStep' => 2,
            ],
            'quote' => [
                'approval_requested' => true,
            ],
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
            // Store resolved location in meta for future use (only if it changed)
            if (($meta['locationId'] ?? '') !== $resolvedLocation) {
                $this->updateMeta($estimateId, ['locationId' => $resolvedLocation]);
            }
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

        // Auto-sync invoice to Xero if connected (non-blocking)
        if (!empty($invoice['id']) && $resolvedLocation) {
            $this->syncInvoiceToXero($estimateId, $invoice['id'], $resolvedLocation);
        }

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

    /**
     * Book installation date/time for an accepted estimate
     * Transitions workflow from "accepted" to "booked"
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array{date: string, time: string, notes?: string} $bookingData Booking information
     * @return array|WP_Error
     */
    public function bookJob(string $estimateId, string $locationId = '', array $bookingData = [])
    {
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        $meta = $this->getMeta($estimateId);
        
        // Validate estimate is accepted
        $quoteStatus = $meta['quote']['status'] ?? 'sent';
        if ($quoteStatus !== 'accepted') {
            return new WP_Error(
                'invalid_status',
                __('Estimate must be accepted before booking. Current status: ' . $quoteStatus, 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Validate booking data
        $scheduledDate = sanitize_text_field($bookingData['date'] ?? '');
        $scheduledTime = sanitize_text_field($bookingData['time'] ?? '');
        $notes = sanitize_text_field($bookingData['notes'] ?? '');

        if (!$scheduledDate || !$scheduledTime) {
            return new WP_Error('bad_request', __('Date and time are required', 'cheapalarms'), ['status' => 400]);
        }

        // Combine date and time
        $scheduledDateTime = $scheduledDate . ' ' . $scheduledTime;
        $timestamp = strtotime($scheduledDateTime);
        if (!$timestamp) {
            return new WP_Error('bad_request', __('Invalid date/time format', 'cheapalarms'), ['status' => 400]);
        }
        
        // SECURITY: Prevent booking in the past
        $currentTimestamp = current_time('timestamp');
        if ($timestamp < $currentTimestamp) {
            return new WP_Error(
                'invalid_date',
                __('Booking date cannot be in the past. Please select a future date.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Update booking data
        $booking = [
            'scheduledDate' => $scheduledDate,
            'scheduledTime' => $scheduledTime,
            'scheduledDateTime' => date('Y-m-d H:i:s', $timestamp),
            'notes' => $notes,
            'status' => 'scheduled',
            'bookedAt' => current_time('mysql'),
        ];

        // Update workflow status to "booked"
        $workflow = $meta['workflow'] ?? [];
        $workflow['status'] = 'booked';
        $workflow['currentStep'] = 4;
        $workflow['bookedAt'] = current_time('mysql');
        
        // Preserve existing timestamps
        if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
            $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
        }
        if (!isset($workflow['reviewedAt']) && isset($meta['workflow']['reviewedAt'])) {
            $workflow['reviewedAt'] = $meta['workflow']['reviewedAt'];
        }
        if (!isset($workflow['acceptedAt']) && isset($meta['workflow']['acceptedAt'])) {
            $workflow['acceptedAt'] = $meta['workflow']['acceptedAt'];
        }

        // Update meta
        $this->updateMeta($estimateId, [
            'booking' => $booking,
            'workflow' => $workflow,
        ]);

        $this->logger->info('Job booked successfully', [
            'estimateId' => $estimateId,
            'scheduledDateTime' => $scheduledDateTime,
        ]);

        // Send booking confirmation email (non-blocking)
        if ($locationId) {
            $this->sendBookingConfirmationEmail($estimateId, $locationId, $booking);
        }

        return [
            'ok' => true,
            'booking' => $booking,
            'workflow' => $workflow,
        ];
    }

    /**
     * Confirm payment for a booked estimate
     * Transitions workflow from "booked" to "paid"
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array{amount: float, provider?: string, transactionId?: string} $paymentData Payment information
     * @return array|WP_Error
     */
    public function confirmPayment(string $estimateId, string $locationId = '', array $paymentData = [])
    {
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }

        // SECURITY: Use lock to prevent race conditions during payment confirmation
        $lockKey = 'ca_payment_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 10 seconds - previous process likely crashed)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 10) {
                // Lock is stale - clear it and proceed
                delete_transient($lockKey);
                $this->logger->warning('Cleared stale payment confirmation lock', [
                    'estimateId' => $estimateId,
                    'lockAge' => $lockAge,
                ]);
            } else {
                // Lock is active - another request is processing
                // Check if payment was already confirmed
                $meta = $this->getMeta($estimateId);
                $existingPayment = $meta['payment'] ?? null;
                if (!empty($existingPayment['status']) && $existingPayment['status'] === 'paid') {
                    return [
                        'ok' => true,
                        'payment' => $existingPayment,
                        'alreadyPaid' => true,
                    ];
                }
                // If not paid yet, return error to prevent duplicate processing
                return new WP_Error(
                    'processing',
                    __('Another request is currently processing this payment. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                );
            }
        }
        
        // Set lock with timestamp
        set_transient($lockKey, time(), 10);

        try {
            $locationId = $locationId ?: $this->config->getLocationId();
            $meta = $this->getMeta($estimateId);
            
            // SECURITY: Check if payment is already confirmed (duplicate payment protection)
            $existingPayment = $meta['payment'] ?? null;
            if (!empty($existingPayment['status']) && $existingPayment['status'] === 'paid') {
                delete_transient($lockKey);
                return [
                    'ok' => true,
                    'payment' => $existingPayment,
                    'alreadyPaid' => true,
                ];
            }
            
            // Validate estimate is booked
            $workflowStatus = $meta['workflow']['status'] ?? 'requested';
            if ($workflowStatus !== 'booked') {
                delete_transient($lockKey);
                return new WP_Error(
                    'invalid_status',
                    __('Estimate must be booked before payment. Current status: ' . $workflowStatus, 'cheapalarms'),
                    ['status' => 400]
                );
            }

            // Get invoice to validate payment amount
            $invoice = $meta['invoice'] ?? null;
            if (!$invoice) {
                delete_transient($lockKey);
                return new WP_Error('bad_request', __('Invoice not found for this estimate', 'cheapalarms'), ['status' => 400]);
            }
            
            // Get invoice total for validation
            $invoiceTotal = null;
            if (isset($invoice['ghl']['total'])) {
                $invoiceTotal = (float) $invoice['ghl']['total'];
            } elseif (isset($invoice['total'])) {
                $invoiceTotal = (float) $invoice['total'];
            }
            
            if ($invoiceTotal === null || $invoiceTotal <= 0) {
                delete_transient($lockKey);
                return new WP_Error('bad_request', __('Invalid invoice total. Cannot process payment.', 'cheapalarms'), ['status' => 400]);
            }
            
            // SECURITY: For Stripe payments, validate transactionId matches stored payment intent ID
            $provider = sanitize_text_field($paymentData['provider'] ?? 'mock');
            $transactionId = sanitize_text_field($paymentData['transactionId'] ?? null);
            
            if ($provider === 'stripe' && !empty($transactionId)) {
                $expiresAt = $meta['payment']['paymentIntentExpiresAt'] ?? null;
                if (!empty($expiresAt) && time() > (int) $expiresAt) {
                    delete_transient($lockKey);
                    return new WP_Error(
                        'payment_intent_expired',
                        __('Payment intent has expired. Please create a new payment intent.', 'cheapalarms'),
                        ['status' => 400]
                    );
                }

                // SECURITY: Check if this payment intent was already used (prevent duplicate payment intent usage)
                // This check must come FIRST before checking stored payment intent ID, because after a payment
                // is confirmed, the paymentIntentId is cleared to allow new payment intents
                $existingPayments = $meta['payment']['payments'] ?? [];
                if (is_array($existingPayments)) {
                    foreach ($existingPayments as $prevPayment) {
                        if (!empty($prevPayment['transactionId']) && $prevPayment['transactionId'] === $transactionId) {
                            delete_transient($lockKey);
                            $this->logger->warning('Payment intent already used', [
                                'estimateId' => $estimateId,
                                'transactionId' => $transactionId,
                            ]);
                            return new WP_Error(
                                'payment_intent_already_used',
                                __('This payment intent has already been used. Please create a new payment intent for additional payments.', 'cheapalarms'),
                                ['status' => 400]
                            );
                        }
                    }
                }
                
                // SECURITY: Validate transactionId matches stored payment intent ID (if one exists)
                // Note: After a payment is confirmed, paymentIntentId is cleared to allow new payment intents
                // So this check only applies if a payment intent was recently created but not yet confirmed
                $storedPaymentIntentId = $meta['payment']['paymentIntentId'] ?? null;
                if (!empty($storedPaymentIntentId) && $transactionId !== $storedPaymentIntentId) {
                    delete_transient($lockKey);
                    $this->logger->warning('Transaction ID mismatch in payment confirmation', [
                        'estimateId' => $estimateId,
                        'providedTransactionId' => $transactionId,
                        'storedPaymentIntentId' => $storedPaymentIntentId,
                    ]);
                    return new WP_Error(
                        'transaction_mismatch',
                        __('Transaction ID does not match the payment intent for this estimate. Please create a new payment intent for additional payments.', 'cheapalarms'),
                        ['status' => 400]
                    );
                }
                
                // SECURITY: For Stripe payments, validate amount against actual payment intent amount from Stripe
                // This prevents frontend amount manipulation
                $stripeService = $this->container->get(\CheapAlarms\Plugin\Services\StripeService::class);
                $paymentIntentResult = $stripeService->getPaymentIntent($transactionId);
                
                if (is_wp_error($paymentIntentResult)) {
                    delete_transient($lockKey);
                    $this->logger->error('Failed to retrieve payment intent from Stripe', [
                        'estimateId' => $estimateId,
                        'paymentIntentId' => $transactionId,
                        'error' => $paymentIntentResult->get_error_message(),
                    ]);
                    return new WP_Error(
                        'stripe_verification_failed',
                        __('Failed to verify payment with Stripe. Please contact support.', 'cheapalarms'),
                        ['status' => 500]
                    );
                }
                
                // Get actual payment amount from Stripe (already converted from cents to dollars)
                $actualPaymentAmount = $paymentIntentResult['amount'] ?? 0;
                
                // Verify payment intent status is succeeded
                if (($paymentIntentResult['status'] ?? 'unknown') !== 'succeeded') {
                    delete_transient($lockKey);
                    return new WP_Error(
                        'payment_not_succeeded',
                        __('Payment was not successful. Please try again.', 'cheapalarms'),
                        ['status' => 400]
                    );
                }
                
                // Use actual payment amount from Stripe, not frontend-provided amount
                $amount = $actualPaymentAmount;
            } else {
                // For non-Stripe payments, get amount from payment data or use invoice total
                $amount = isset($paymentData['amount']) ? (float) $paymentData['amount'] : $invoiceTotal;
            }
            
            if ($amount <= 0) {
                delete_transient($lockKey);
                return new WP_Error('bad_request', __('Payment amount must be greater than zero', 'cheapalarms'), ['status' => 400]);
            }
            
            // SECURITY: Calculate cumulative payment amount (for partial payment tracking)
            $existingPaidAmount = 0;
            if (!empty($existingPayment['amount']) && $existingPayment['status'] === 'paid') {
                // If already paid, use existing amount (shouldn't happen due to duplicate check above, but defensive)
                $existingPaidAmount = (float) $existingPayment['amount'];
            } elseif (!empty($meta['payment']['payments']) && is_array($meta['payment']['payments'])) {
                // Sum all previous partial payments
                foreach ($meta['payment']['payments'] as $prevPayment) {
                    if (!empty($prevPayment['amount'])) {
                        $existingPaidAmount += (float) $prevPayment['amount'];
                    }
                }
            }
            
            $totalPaidAmount = $existingPaidAmount + $amount;
            
            // SECURITY: Validate cumulative payment amount against invoice total
            // Allow partial payments (up to invoice total), but prevent overpayment
            if ($totalPaidAmount > $invoiceTotal) {
                delete_transient($lockKey);
                
                // If Stripe already charged, attempt a refund to avoid over-collection
                if ($provider === 'stripe' && !empty($transactionId)) {
                    try {
                        $stripeService = $this->container->get(\CheapAlarms\Plugin\Services\StripeService::class);
                        $refundResult = $stripeService->refundPaymentIntent($transactionId, 'requested_by_customer', $amount);
                        if (is_wp_error($refundResult)) {
                            $this->logger->error('Failed to refund over-collected Stripe payment', [
                                'estimateId' => $estimateId,
                                'transactionId' => $transactionId,
                                'error' => $refundResult->get_error_message(),
                                'invoiceTotal' => $invoiceTotal,
                                'existingPaidAmount' => $existingPaidAmount,
                                'attemptedAmount' => $amount,
                            ]);
                        } else {
                            $this->logger->warning('Refunded Stripe payment due to overpayment validation', [
                                'estimateId' => $estimateId,
                                'transactionId' => $transactionId,
                                'refundStatus' => $refundResult['status'] ?? null,
                                'refundAmount' => $refundResult['amount'] ?? null,
                            ]);
                        }
                    } catch (\Exception $refundException) {
                        $this->logger->error('Exception during Stripe refund after validation failure', [
                            'estimateId' => $estimateId,
                            'transactionId' => $transactionId,
                            'exception' => $refundException->getMessage(),
                        ]);
                    }
                }

                return new WP_Error(
                    'payment_exceeds_invoice',
                    sprintf(
                        __('Total payment amount (%.2f) exceeds invoice total (%.2f). Remaining balance: %.2f', 'cheapalarms'),
                        $totalPaidAmount,
                        $invoiceTotal,
                        max(0, $invoiceTotal - $existingPaidAmount)
                    ),
                    [
                        'status' => 400,
                        'invoiceTotal' => $invoiceTotal,
                        'existingPaidAmount' => $existingPaidAmount,
                        'amountProvided' => $amount,
                        'totalPaidAmount' => $totalPaidAmount,
                        'remainingBalance' => max(0, $invoiceTotal - $existingPaidAmount),
                    ]
                );
            }

            // Update payment data
            // Track individual payments for partial payment support
            $paymentRecord = [
                'amount' => $amount,
                'provider' => sanitize_text_field($paymentData['provider'] ?? 'mock'),
                'transactionId' => sanitize_text_field($paymentData['transactionId'] ?? null),
                'paidAt' => current_time('mysql'),
            ];
            
            // Initialize payments array if it doesn't exist
            $payments = $meta['payment']['payments'] ?? [];
            if (!is_array($payments)) {
                $payments = [];
            }
            
            // Add this payment to the payments array
            $payments[] = $paymentRecord;
            
            // Determine if invoice is fully paid
            $isFullyPaid = abs($totalPaidAmount - $invoiceTotal) < 0.01; // Tolerance for floating point
            
            // Update payment data structure
            $payment = [
                'amount' => $totalPaidAmount, // Total amount paid (cumulative)
                'status' => $isFullyPaid ? 'paid' : 'partial',
                'provider' => $provider,
                'transactionId' => $transactionId,
                'paidAt' => current_time('mysql'),
                'payments' => $payments, // Array of individual payment records
                'invoiceTotal' => $invoiceTotal,
                'remainingBalance' => max(0, $invoiceTotal - $totalPaidAmount),
                // SECURITY: Clear paymentIntentId after payment is confirmed to allow creating new payment intents
                // The payment intent ID is preserved in the payments array for tracking
                'paymentIntentId' => null,
                'paymentIntentExpiresAt' => null,
            ];

            // Update workflow status to "paid" only if fully paid
            $workflow = $meta['workflow'] ?? [];
            if ($isFullyPaid) {
                $workflow['status'] = 'paid';
                $workflow['currentStep'] = 5;
                $workflow['paidAt'] = current_time('mysql');
            } else {
                // Keep status as "booked" if partial payment
                $workflow['status'] = 'booked';
            }
            
            // Preserve existing timestamps
            if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
                $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
            }
            if (!isset($workflow['reviewedAt']) && isset($meta['workflow']['reviewedAt'])) {
                $workflow['reviewedAt'] = $meta['workflow']['reviewedAt'];
            }
            if (!isset($workflow['acceptedAt']) && isset($meta['workflow']['acceptedAt'])) {
                $workflow['acceptedAt'] = $meta['workflow']['acceptedAt'];
            }
            if (!isset($workflow['bookedAt']) && isset($meta['workflow']['bookedAt'])) {
                $workflow['bookedAt'] = $meta['workflow']['bookedAt'];
            }

            // Update meta
            $this->updateMeta($estimateId, [
                'payment' => $payment,
                'workflow' => $workflow,
            ]);
            
            // Release lock
            delete_transient($lockKey);

            if (defined('WP_DEBUG') && WP_DEBUG) {
                $this->logger->info('Payment confirmed successfully', [
                    'estimateId' => $estimateId,
                    'amount' => $amount,
                    'totalPaidAmount' => $totalPaidAmount,
                    'isFullyPaid' => $isFullyPaid,
                ]);
            }

            // Record payment in Xero if invoice was synced to Xero
            // SECURITY: xeroInvoiceId is already validated as it comes from invoice meta linked to this estimate
            // The invoice was retrieved above and belongs to this estimateId, so xeroInvoiceId is safe
            $xeroInvoiceId = $invoice['xeroInvoiceId'] ?? null;
            
            if ($xeroInvoiceId) {
                $xeroService = $this->container->get(\CheapAlarms\Plugin\Services\XeroService::class);
                
                // Check if Xero is connected
                if ($xeroService->isConnected()) {
                    $paymentMethod = $payment['provider'] === 'stripe' ? 'Stripe' : ($payment['provider'] ?? 'Manual');
                    $transactionId = $payment['transactionId'] ?? '';
                    
                    // SECURITY: xeroInvoiceId is validated - it comes from invoice meta that belongs to this estimate
                    // No additional validation needed as the invoice was already retrieved from this estimate's meta
                    $xeroPaymentResult = $xeroService->recordPayment(
                        $xeroInvoiceId,
                        $amount,
                        $paymentMethod,
                        $transactionId
                    );
                    
                    if (is_wp_error($xeroPaymentResult)) {
                        // Log error but don't fail the payment confirmation
                        $this->logger->error('Failed to record payment in Xero', [
                            'estimateId' => $estimateId,
                            'xeroInvoiceId' => $xeroInvoiceId,
                            'amount' => $amount,
                            'error' => $xeroPaymentResult->get_error_message(),
                        ]);
                    } else {
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        $this->logger->info('Payment recorded in Xero', [
                            'estimateId' => $estimateId,
                            'xeroInvoiceId' => $xeroInvoiceId,
                            'xeroPaymentId' => $xeroPaymentResult['paymentId'] ?? null,
                            'amount' => $amount,
                        ]);
                    }
                    }
                } else {
                    $this->logger->warning('Xero invoice ID exists but Xero is not connected', [
                        'estimateId' => $estimateId,
                        'xeroInvoiceId' => $xeroInvoiceId,
                    ]);
                }
            }

            // Send payment confirmation email (non-blocking)
            if ($locationId) {
                $this->sendPaymentConfirmationEmail($estimateId, $locationId, $payment);
            }

            return [
                'ok' => true,
                'payment' => $payment,
                'workflow' => $workflow,
                'isFullyPaid' => $isFullyPaid,
                'remainingBalance' => max(0, $invoiceTotal - $totalPaidAmount),
            ];
        } catch (\Exception $e) {
            // Release lock on error
            delete_transient($lockKey);
            $this->logger->error('Exception during payment confirmation', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return new WP_Error(
                'payment_confirmation_error',
                __('An error occurred while confirming payment. Please try again.', 'cheapalarms'),
                ['status' => 500]
            );
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
        $quote = $meta['quote'] ?? [];
        $photos['total'] = count($uploads);
        $photos['uploaded'] = count($uploads);
        $photos['items'] = $uploads;
        $photos['submission_status'] = 'submitted';
        $photos['submitted_at'] = current_time('mysql');
        $photos['last_edited_at'] = current_time('mysql');
        
        // Update workflow status and auto-request review
        $workflow = $meta['workflow'] ?? [];
        $currentWorkflowStatus = $workflow['status'] ?? 'requested';
        
        // Check if changes were requested (indicates resubmission after admin review)
        $changesWereRequested = !empty($quote['change_requested_at']);
        
        // Auto-request review when photos are submitted (if not already requested)
        // BUT: Don't auto-request if changes were requested (customer must manually request review)
        $autoRequestReview = empty($quote['approval_requested']) && !$changesWereRequested;
        
        // If this is the first submission (not a resubmission), auto-request review
        if ($autoRequestReview) {
            $quote['approval_requested'] = true;
            if ($currentWorkflowStatus === 'requested' || $currentWorkflowStatus === 'sent') {
                $workflow['status'] = 'under_review';
                $workflow['currentStep'] = 2;
            }
        } else {
            // Resubmission after admin reviewed - keep workflow status as 'sent' (customer needs to request review)
            // Only transition to 'under_review' if review was already requested
            if ($currentWorkflowStatus === 'requested' || $currentWorkflowStatus === 'sent') {
                if (!empty($quote['approval_requested'])) {
                    $workflow['status'] = 'under_review';
                    $workflow['currentStep'] = 2;
                }
                // If changes were requested and review not yet requested, stay in 'sent' status
            }
        }
        
        // Preserve requestedAt if it exists
        if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
            $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
        }
        
        // Update meta using updateMeta() for proper locking (not update_option directly)
        $this->updateMeta($estimateId, [
            'photos' => $photos,
            'workflow' => $workflow,
            'quote' => $quote,
        ]);
        
        // Send notification to admin
        // If auto-requested review, send review request notification instead of just photo submission
        if ($autoRequestReview) {
            $this->sendReviewRequestNotificationToAdmin($estimateId, $locationId, $quote, $photos);
        } else {
            $this->sendPhotoSubmissionNotificationToAdmin($estimateId, $locationId, $photos['total']);
        }
        
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

        $token     = self::generateToken();
        $expiresAt = current_time('timestamp') + DAY_IN_SECONDS * 7;
        $portalUrl = $this->resolvePortalUrl($estimateId, $token);

        // SECURITY: Hash token before storage to prevent disclosure if database is compromised
        $tokenHash = self::hashInviteToken($token);
        
        $accountMeta = [
            'status'      => 'active',
            'statusLabel' => 'Account active',
            'lastInviteAt'=> current_time('mysql'),
            'canResend'   => true,
            'portalUrl'   => $portalUrl,
            'inviteToken' => $tokenHash, // Store hash, not plaintext
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
    /**
     * Link estimate to existing user account
     * SECURITY: This method should only be called in trusted contexts:
     * - Admin operations (estimate creation)
     * - User-initiated actions (password reset with valid estimateId)
     * - Invite token validation (user proving access via invite link)
     * 
     * @param string $estimateId Estimate ID to link
     * @param int $userId User ID to link estimate to
     * @param string|null $locationId Optional location ID
     * @return array|WP_Error
     */
    public function linkEstimateToExistingAccount(string $estimateId, int $userId, ?string $locationId = null): array|WP_Error
    {
        // SECURITY: Basic validation - verify user exists
        $user = get_user_by('id', $userId);
        if (!$user) {
            return new WP_Error('user_not_found', __('User not found.', 'cheapalarms'), ['status' => 404]);
        }
        
        // Attach estimate to user
        $this->attachEstimateToUser($userId, $estimateId, $locationId);
        
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
        
        // SECURITY: Always generate new token for resend (token rotation)
        // This invalidates old invite links, which is a security feature
        // Old links will fail validation, forcing users to use the latest invite
        $token = self::generateToken();
        $tokenHash = self::hashInviteToken($token);
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
                'inviteToken'  => $tokenHash, // Store hash, not plaintext
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
     * Get dashboard status from portal meta only (no GHL API calls)
     * Fast read-only method for dashboard listing
     * 
     * @param string $estimateId Estimate ID
     * @param array $meta Portal meta array
     * @return array Dashboard status data
     */
    private function getDashboardStatusFromMeta(string $estimateId, array $meta): array
    {
        $quote = $meta['quote'] ?? [];
        $account = $meta['account'] ?? [];
        
        return [
            'estimateId'   => $estimateId,
            'quote'        => [
                'status'      => $quote['status'] ?? 'sent',
                'statusLabel' => $quote['statusLabel'] ?? 'Sent',
                'number'      => $quote['number'] ?? $estimateId, // Fallback to ID if number not stored
                'acceptedAt'  => $quote['acceptedAt'] ?? null,
            ],
            'account'      => [
                'portalUrl'    => $account['portalUrl'] ?? null,
                'resetUrl'     => $account['resetUrl'] ?? null,
                'lastInviteAt' => $account['lastInviteAt'] ?? null,
            ],
            'invoice'      => $meta['invoice'] ?? null,
        ];
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

        // PHASE 1: Collect all unique estimate IDs and normalize to strings
        $uniqueEstimateIds = array_filter(
            array_unique(array_map('strval', $estimateIds), SORT_REGULAR),
            fn($id) => !empty($id)
        );
        
        // PHASE 2: Batch fetch all portal meta in ONE query (prevents N+1)
        $allMeta = [];
        if (!empty($uniqueEstimateIds)) {
            $portalMetaRepo = $this->container->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class);
            $allMeta = $portalMetaRepo->batchGet($uniqueEstimateIds);
        }

        // PHASE 3: Process estimates with pre-fetched meta
        $items = [];
        foreach ($uniqueEstimateIds as $estimateId) {
            if (!$estimateId) {
                continue;
            }

            // $estimateId is already normalized to string from PHASE 1
            $locationId = $locations[$estimateId] ?? '';
            
            // Use pre-fetched meta instead of getMeta()
            $meta = $allMeta[$estimateId] ?? [];
            if (empty($meta)) {
                // Skip estimates with no portal meta
                continue;
            }

            $status = $this->getDashboardStatusFromMeta($estimateId, $meta);
            $items[] = array_merge($status, [
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
                
                // Check if value actually changed (update_option returns false if no change)
                $currentJson = wp_json_encode($current);
                $mergedJson = wp_json_encode($merged);
                
                // Validate JSON encoding succeeded (wp_json_encode returns false on failure)
                if ($currentJson === false || $mergedJson === false) {
                    delete_transient($lockKey);
                    $this->logger->error('Failed to encode portal meta JSON', [
                        'estimateId' => $estimateId,
                        'currentError' => json_last_error_msg(),
                        'mergedError' => json_last_error_msg(),
                    ]);
                    return false;
                }
                
                $valueChanged = ($currentJson !== $mergedJson);
                
                // Update atomically
                $result = update_option(self::OPTION_PREFIX . $estimateId, $mergedJson, false);
                
                // Release lock
                delete_transient($lockKey);
                
                // Only log warning if value changed but update failed
                // update_option() returns false when value hasn't changed, which is normal
                if (!$result && $valueChanged) {
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

    /**
     * Validate invite token with expiration check
     * @return array{valid: bool, reason: string, message: string, expiresAt: ?string}
     */
    public function validateInviteToken(string $estimateId, string $token): array
    {
        if (!$estimateId || !$token) {
            return [
                'valid' => false,
                'reason' => 'missing_params',
                'message' => __('Invalid invite link parameters.', 'cheapalarms'),
                'expiresAt' => null,
            ];
        }

        $meta = $this->getMeta($estimateId);
        $accountToken = $meta['account']['inviteToken'] ?? null;
        $expiresAt = $meta['account']['expiresAt'] ?? null;

        // SECURITY: Verify token using secure comparison (supports both hashed and legacy plaintext)
        if (!is_string($accountToken) || !self::verifyInviteToken($token, $accountToken)) {
            $this->logger->warning('Invalid invite token', [
                'estimateId' => $estimateId,
                'tokenProvided' => substr($token, 0, 8) . '...',
            ]);
            return [
                'valid' => false,
                'reason' => 'invalid_token',
                'message' => __('This invite link is invalid. Please use the link from your email.', 'cheapalarms'),
                'expiresAt' => $expiresAt,
            ];
        }
        
        // SECURITY: Upgrade legacy plaintext tokens to hashed format (one-time migration)
        // Only upgrade if stored token is plaintext (not a hash)
        if (!preg_match('/^\$2[ayb]\$/', $accountToken)) {
            $tokenHash = self::hashInviteToken($token);
            $this->updateMeta($estimateId, [
                'account' => array_merge($meta['account'] ?? [], [
                    'inviteToken' => $tokenHash,
                ]),
            ]);
            $this->logger->info('Upgraded invite token to hashed format', [
                'estimateId' => $estimateId,
            ]);
        }

        // Check expiration
        if ($expiresAt) {
            $expiryTimestamp = strtotime($expiresAt);
            if ($expiryTimestamp && time() > $expiryTimestamp) {
                $daysExpired = floor((time() - $expiryTimestamp) / DAY_IN_SECONDS);
                $this->logger->info('Expired invite token', [
                    'estimateId' => $estimateId,
                    'expiredDaysAgo' => $daysExpired,
                ]);
                return [
                    'valid' => false,
                    'reason' => 'expired',
                    'message' => sprintf(
                        __('This invite link expired %d day(s) ago. Please request a new link.', 'cheapalarms'),
                        $daysExpired
                    ),
                    'expiresAt' => $expiresAt,
                ];
            }
        }

        return [
            'valid' => true,
            'reason' => 'valid',
            'message' => '',
            'expiresAt' => $expiresAt,
        ];
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

        // Get estimate number if estimateId is provided
        $estimateNumber = '';
        if ($estimateId && $locationId) {
            try {
                $estimate = $this->estimateService->getEstimate([
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                if (!is_wp_error($estimate)) {
                    $estimateNumber = $estimate['estimateNumber'] ?? '';
                }
            } catch (\Exception $e) {
                // Ignore errors, use empty estimate number
            }
        }

        // Get user context for email personalization
        $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

        // Render context-aware email template
        $emailTemplate = null;
        try {
            $emailTemplateService = $this->container->get(EmailTemplateService::class);
            $emailData = [
                'customerName' => $name,
                'portalUrl' => $portalUrl,
                'resetUrl' => $resetUrl,
                'isResend' => $isResend,
                'estimateNumber' => $estimateNumber,
            ];

            $emailTemplate = $emailTemplateService->renderPortalInviteEmail($userContext, $emailData);
            $subject = $emailTemplate['subject'] ?? ($isResend ? __('CheapAlarms portal invite (resent)', 'cheapalarms') : __('Your CheapAlarms portal is ready', 'cheapalarms'));
            $body = $emailTemplate['body'] ?? '';

            // Fallback if template rendering failed
            if (empty($body)) {
                error_log('[CheapAlarms][WARNING] Portal invite email template returned empty body, using fallback');
                $subject = $isResend
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $name)) . '</p>';
                $body .= '<p>' . esc_html(__('We have prepared your CheapAlarms portal. Use the secure links below to access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
                $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';
                if ($resetUrl) {
                    $body .= '<p><a href="' . esc_url($resetUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('Set your password', 'cheapalarms')) . '</a></p>';
                }
                $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }
        } catch (\Exception $e) {
            error_log('[CheapAlarms][ERROR] Failed to render portal invite email template: ' . $e->getMessage());
            // Fallback to simple email
            $subject = $isResend
                ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                : __('Your CheapAlarms portal is ready', 'cheapalarms');
            $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $name)) . '</p>';
            $body .= '<p>' . esc_html(__('We have prepared your CheapAlarms portal. Use the secure links below to access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
            $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('Open your portal', 'cheapalarms')) . '</a></p>';
            if ($resetUrl) {
                $body .= '<p><a href="' . esc_url($resetUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('Set your password', 'cheapalarms')) . '</a></p>';
            }
            $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
            $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
        }

        // Send via GHL if contactId available (all customer emails must use GHL)
        $sent = false;
        if ($contactId) {
            $result = $this->sendEmailViaGhl($contactId, $subject, $body);
            if (is_wp_error($result)) {
                $this->logger->error('Failed to send portal invite email via GHL', [
                    'email' => $email,
                    'contactId' => $contactId,
                    'error' => $result->get_error_message(),
                    'error_code' => $result->get_error_code(),
                ]);
                $sent = false;
            } else {
                $sent = $result === true;
            }
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
                        $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                        if (is_wp_error($result)) {
                            $this->logger->error('Failed to send portal invite email via GHL', [
                                'email' => $email,
                                'contactId' => $contactId,
                                'error' => $result->get_error_message(),
                                'error_code' => $result->get_error_code(),
                            ]);
                            $sent = false;
                        } else {
                            $sent = $result === true;
                        }
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

        $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
        $this->logger->info('Portal invite email sent', [
            'email'     => $email,
            'userId'    => $userId,
            'resend'    => $isResend,
            'contactId' => $contactId,
            'sentViaGhl' => $contactId ? true : false,
            'sent'      => $sent,
            'variation' => $variation,
        ]);

        return $resetUrl;
    }

    /**
     * Send email via GoHighLevel Conversations API
     * 
     * @param string $contactId GHL contact ID
     * @param string $subject Email subject
     * @param string $htmlBody Email HTML body
     * @return bool|WP_Error Returns true on success, WP_Error on failure with specific error codes
     */
    private function sendEmailViaGhl(string $contactId, string $subject, string $htmlBody): bool|WP_Error
    {
        try {
            if (empty($contactId)) {
                return new WP_Error(
                    'email_contact_missing',
                    __('Cannot send email: Contact ID is missing.', 'cheapalarms'),
                    ['status' => 400]
                );
            }

            $ghlClient = $this->container->get(GhlClient::class);
            $fromEmail = get_option('ghl_from_email', 'quotes@cheapalarms.com.au');
            
            // Ensure subject is never empty (GHL might use from email as fallback)
            if (empty($subject) || trim($subject) === '') {
                $subject = __('CheapAlarms Notification', 'cheapalarms');
            }
            
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
                $errorCode = $result->get_error_code();
                $errorData = $result->get_error_data();
                $httpCode = $errorData['code'] ?? 500;
                $body = $errorData['body'] ?? '';
                
                // Parse GHL error response to extract meaningful message
                $ghlMessage = $this->parseGhlErrorMessage($body, $httpCode);
                
                $this->logger->error('GHL email API failed', [
                    'contactId' => $contactId,
                    'subject' => $subject,
                    'error' => $result->get_error_message(),
                    'httpCode' => $httpCode,
                    'ghlMessage' => $ghlMessage,
                ]);
                
                // Return specific error based on HTTP code and message
                if ($httpCode === 400) {
                    // 400 usually means invalid email or contact issue
                    if (stripos($ghlMessage, 'email') !== false || stripos($ghlMessage, 'invalid') !== false) {
                        return new WP_Error(
                            'email_invalid',
                            sprintf(__('Invalid email address: %s', 'cheapalarms'), $ghlMessage ?: __('The email address appears to be invalid or undeliverable.', 'cheapalarms')),
                            ['status' => 400, 'ghl_message' => $ghlMessage]
                        );
                    }
                    return new WP_Error(
                        'email_bad_request',
                        sprintf(__('Email sending failed: %s', 'cheapalarms'), $ghlMessage ?: __('Invalid request to email service.', 'cheapalarms')),
                        ['status' => 400, 'ghl_message' => $ghlMessage]
                    );
                }
                
                if ($httpCode === 404) {
                    return new WP_Error(
                        'email_contact_not_found',
                        __('Contact not found in email service. This may indicate a dummy or invalid email address.', 'cheapalarms'),
                        ['status' => 404, 'ghl_message' => $ghlMessage]
                    );
                }
                
                // Generic GHL API error
                return new WP_Error(
                    'ghl_api_error',
                    sprintf(__('Email service error: %s', 'cheapalarms'), $ghlMessage ?: __('Unable to send email. Please try again.', 'cheapalarms')),
                    ['status' => $httpCode, 'ghl_message' => $ghlMessage]
                );
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
            return new WP_Error(
                'email_exception',
                __('An unexpected error occurred while sending email.', 'cheapalarms'),
                ['status' => 500, 'exception' => $e->getMessage()]
            );
        }
    }

    /**
     * Parse GHL error response to extract user-friendly message
     * 
     * @param string $body Response body from GHL API
     * @param int $httpCode HTTP status code
     * @return string Parsed error message
     */
    private function parseGhlErrorMessage(string $body, int $httpCode): string
    {
        if (empty($body)) {
            return '';
        }
        
        // Try to parse JSON response
        $decoded = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            // GHL error structure: { "message": "...", "error": "...", "statusCode": 400 }
            $message = $decoded['message'] ?? $decoded['error'] ?? '';
            if (!empty($message)) {
                return $message;
            }
        }
        
        // Fallback: return first 200 chars of body (sanitized)
        return substr(strip_tags($body), 0, 200);
    }

    /**
     * Send estimate email to contact
     * 
     * @param string $estimateId Estimate ID
     * @param array $contact Contact array with email and id
     * @param string $locationId GHL location ID
     * @param string $portalUrl Portal URL for the estimate
     * @param string|null $resetUrl Optional password reset URL
     * @return bool|WP_Error Returns true on success, WP_Error on failure with specific error codes
     */
    public function sendEstimateEmail(string $estimateId, array $contact, string $locationId, string $portalUrl, ?string $resetUrl = null): bool|WP_Error
    {
        $email = sanitize_email($contact['email'] ?? '');
        if (!$email) {
            $this->logger->warning('Cannot send estimate email: No contact email', [
                'estimateId' => $estimateId,
            ]);
            return new WP_Error(
                'email_missing',
                __('Cannot send estimate: Contact email address is missing.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        $contactId = $contact['id'] ?? null;
        if (!$contactId) {
            $this->logger->warning('Cannot send estimate email: No GHL contact ID', [
                'estimateId' => $estimateId,
                'email' => $email,
            ]);
            return new WP_Error(
                'contact_missing',
                __('Cannot send estimate: Contact is missing GHL contact ID. This may indicate a dummy or invalid email address. Please ensure the contact has a valid email address in GoHighLevel.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Get estimate details for email content
        $estimate = $this->estimateService->getEstimate([
            'estimateId' => $estimateId,
            'locationId' => $locationId,
        ]);

        $estimateNumber = null;
        if (!is_wp_error($estimate)) {
            $estimateNumber = $estimate['estimateNumber'] ?? $estimate['id'] ?? $estimateId;
        }

        $displayName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
        
        // Get user ID from email
        $userId = email_exists($email);
        
        // Get user context for email personalization
        $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

        // Render context-aware email template
        $emailTemplate = null;
        try {
            $emailTemplateService = $this->container->get(EmailTemplateService::class);
            $emailData = [
                'customerName' => $displayName,
                'estimateNumber' => $estimateNumber,
                'portalUrl' => $portalUrl,
                'resetUrl' => $resetUrl,
            ];

            $emailTemplate = $emailTemplateService->renderEstimateEmail($userContext, $emailData);
            $subject = $emailTemplate['subject'] ?? ($estimateNumber ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber) : __('Your estimate is ready', 'cheapalarms'));
            $body = $emailTemplate['body'] ?? '';

            // Fallback if template rendering failed
            if (empty($body)) {
                error_log('[CheapAlarms][WARNING] Estimate email template returned empty body, using fallback');
                $subject = $estimateNumber 
                    ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                    : __('Your estimate is ready', 'cheapalarms');
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $displayName)) . '</p>';
                if ($estimateNumber) {
                    $body .= '<p>' . esc_html(sprintf(
                        __('Your estimate #%s is ready for review. Click the button below to view your estimate and manage your installation:', 'cheapalarms'),
                        $estimateNumber
                    )) . '</p>';
                } else {
                    $body .= '<p>' . esc_html(__('Your estimate is ready for review. Click the button below to view your estimate and manage your installation:', 'cheapalarms')) . '</p>';
                }
                $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('View Your Estimate', 'cheapalarms')) . '</a></p>';
                if ($resetUrl) {
                    $body .= '<p style="margin-top: 16px; color: #64748b; font-size: 14px;">' . esc_html(__('or', 'cheapalarms')) . ' <a href="' . esc_url($resetUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('set your password to access your account', 'cheapalarms')) . '</a></p>';
                }
                $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }
        } catch (\Exception $e) {
            error_log('[CheapAlarms][ERROR] Failed to render estimate email template: ' . $e->getMessage());
            // Fallback to simple email
            $subject = $estimateNumber 
                ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                : __('Your estimate is ready', 'cheapalarms');
            $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $displayName)) . '</p>';
            if ($estimateNumber) {
                $body .= '<p>' . esc_html(sprintf(
                    __('Your estimate #%s is ready for review. Click the button below to view your estimate and manage your installation:', 'cheapalarms'),
                    $estimateNumber
                )) . '</p>';
            } else {
                $body .= '<p>' . esc_html(__('Your estimate is ready for review. Click the button below to view your estimate and manage your installation:', 'cheapalarms')) . '</p>';
            }
            $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('View Your Estimate', 'cheapalarms')) . '</a></p>';
            if ($resetUrl) {
                $body .= '<p style="margin-top: 16px; color: #64748b; font-size: 14px;">' . esc_html(__('or', 'cheapalarms')) . ' <a href="' . esc_url($resetUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('set your password to access your account', 'cheapalarms')) . '</a></p>';
            }
            $body .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
            $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
        }

        // Send via GHL Conversations API
        $sent = $this->sendEmailViaGhl($contactId, $subject, $body);

        // If sendEmailViaGhl returned WP_Error, pass it through
        if (is_wp_error($sent)) {
            return $sent;
        }

        // At this point, sendEmailViaGhl returned true (success)
        $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
        $this->logger->info('Estimate email sent', [
            'estimateId' => $estimateId,
            'estimateNumber' => $estimateNumber,
            'email' => $email,
            'contactId' => $contactId,
            'sent' => true,
            'variation' => $variation,
        ]);

        return true;
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

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'invoiceNumber' => $invoiceNumber,
                    'invoiceUrl' => $invoiceUrl,
                    'invoiceTotal' => $invoiceTotal,
                    'currency' => $currency,
                    'dueDate' => $dueDate,
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderInvoiceEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? __('Your invoice is ready for payment', 'cheapalarms');
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Invoice email template returned empty body, using fallback');
                    $subject = __('Your invoice is ready for payment', 'cheapalarms');
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
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render invoice email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = __('Your invoice is ready for payment', 'cheapalarms');
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
            }

            // Send via GHL instead of wp_mail
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send invoice ready email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for invoice email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
            $this->logger->info('Invoice ready email sent via GHL', [
                'estimateId' => $estimateId,
                'invoiceId' => $invoice['id'] ?? null,
                'contactId' => $contactId,
                'sent' => $sent,
                'variation' => $variation,
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
     * Auto-sync invoice to Xero (non-blocking)
     * Called automatically when GHL invoice is created
     * 
     * @param string $estimateId Estimate ID
     * @param string $ghlInvoiceId GHL invoice ID
     * @param string $locationId Location ID
     * @return void
     */
    private function syncInvoiceToXero(string $estimateId, string $ghlInvoiceId, string $locationId): void
    {
        // Use lock to prevent concurrent sync attempts
        $lockKey = 'ca_xero_sync_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        
        if ($lockValue !== false) {
            // Check if lock is stale (older than 30 seconds)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 30) {
                delete_transient($lockKey);
                $this->logger->warning('Cleared stale Xero sync lock', [
                    'estimateId' => $estimateId,
                    'lockAge' => $lockAge,
                ]);
            } else {
                // Sync already in progress, skip
                $this->logger->info('Xero sync already in progress, skipping', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }
        }
        
        // Set lock
        set_transient($lockKey, time(), 30);
        
        try {
            // Get current meta
            $meta = $this->getMeta($estimateId);
            $invoiceMeta = $meta['invoice'] ?? [];
            
            // Check if already synced successfully
            $xeroSync = $invoiceMeta['xeroSync'] ?? [];
            if (($xeroSync['status'] ?? '') === 'success' && !empty($invoiceMeta['xeroInvoiceId'])) {
                $this->logger->info('Invoice already synced to Xero, skipping auto-sync', [
                    'estimateId' => $estimateId,
                    'xeroInvoiceId' => $invoiceMeta['xeroInvoiceId'],
                ]);
                delete_transient($lockKey);
                return;
            }
            
            // Check if Xero is connected
            $xeroService = $this->container->get(\CheapAlarms\Plugin\Services\XeroService::class);
            if (!$xeroService->isConnected()) {
                // Update status to 'skipped' - Xero not connected
                $invoiceMeta['xeroSync'] = [
                    'status' => 'skipped',
                    'attemptedAt' => current_time('mysql'),
                    'error' => 'Xero not connected',
                ];
                $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
                
                $this->logger->info('Xero auto-sync skipped: Xero not connected', [
                    'estimateId' => $estimateId,
                    'ghlInvoiceId' => $ghlInvoiceId,
                ]);
                delete_transient($lockKey);
                return;
            }
            
            // Check if account codes are configured
            $salesAccountCode = $this->config->getXeroSalesAccountCode();
            if (empty($salesAccountCode)) {
                $invoiceMeta['xeroSync'] = [
                    'status' => 'failed',
                    'attemptedAt' => current_time('mysql'),
                    'error' => 'Sales account code not configured',
                    'retryCount' => ($xeroSync['retryCount'] ?? 0),
                ];
                $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
                
                $this->logger->error('Xero auto-sync failed: Sales account code not configured', [
                    'estimateId' => $estimateId,
                    'ghlInvoiceId' => $ghlInvoiceId,
                ]);
                delete_transient($lockKey);
                return;
            }
            
            // Update status to 'pending'
            $invoiceMeta['xeroSync'] = [
                'status' => 'pending',
                'attemptedAt' => current_time('mysql'),
                'retryCount' => ($xeroSync['retryCount'] ?? 0),
            ];
            $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
            
            $this->logger->info('Xero auto-sync started', [
                'estimateId' => $estimateId,
                'ghlInvoiceId' => $ghlInvoiceId,
            ]);
            
            // Fetch invoice from GHL
            $invoiceService = $this->container->get(\CheapAlarms\Plugin\Services\InvoiceService::class);
            $ghlInvoice = $invoiceService->getInvoice($ghlInvoiceId, $locationId);
            
            if (is_wp_error($ghlInvoice)) {
                $errorMessage = $ghlInvoice->get_error_message();
                $invoiceMeta['xeroSync'] = [
                    'status' => 'failed',
                    'attemptedAt' => current_time('mysql'),
                    'error' => 'Failed to fetch invoice from GHL: ' . $errorMessage,
                    'retryCount' => ($xeroSync['retryCount'] ?? 0) + 1,
                ];
                $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
                
                $this->logger->error('Xero auto-sync failed: Could not fetch invoice from GHL', [
                    'estimateId' => $estimateId,
                    'ghlInvoiceId' => $ghlInvoiceId,
                    'error' => $errorMessage,
                ]);
                delete_transient($lockKey);
                return;
            }
            
            // Extract contact data
            $contact = $ghlInvoice['contact'] ?? [];
            $contactName = trim($contact['name'] ?? '');
            
            // Split name into first and last name
            $firstName = '';
            $lastName = '';
            if (!empty($contactName)) {
                $nameParts = preg_split('/\s+/', $contactName, 2);
                $firstName = $nameParts[0] ?? '';
                $lastName = $nameParts[1] ?? '';
            }
            
            $contactData = [
                'name' => $contactName ?: 'Unknown',
                'email' => $contact['email'] ?? '',
                'firstName' => $firstName,
                'lastName' => $lastName,
                'phone' => $contact['phone'] ?? '',
            ];
            
            // Create invoice in Xero
            $xeroResult = $xeroService->createInvoice($ghlInvoice, $contactData);
            
            if (is_wp_error($xeroResult)) {
                $errorMessage = $xeroResult->get_error_message();
                $errorCode = $xeroResult->get_error_code();
                
                // Handle duplicate invoice - try to retrieve existing invoice ID
                if ($errorCode === 'duplicate_invoice') {
                    $errorData = $xeroResult->get_error_data();
                    $existingXeroInvoiceId = $errorData['xeroInvoiceId'] ?? null;
                    
                    if ($existingXeroInvoiceId) {
                        // Store existing invoice ID
                        $invoiceMeta['xeroInvoiceId'] = $existingXeroInvoiceId;
                        $invoiceMeta['xeroInvoiceNumber'] = $errorData['invoiceNumber'] ?? null;
                        $invoiceMeta['xeroSync'] = [
                            'status' => 'success',
                            'attemptedAt' => current_time('mysql'),
                            'error' => null,
                            'retryCount' => ($xeroSync['retryCount'] ?? 0),
                            'note' => 'Invoice already existed in Xero, using existing invoice',
                        ];
                        $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
                        
                        $this->logger->info('Xero auto-sync succeeded: Using existing invoice', [
                            'estimateId' => $estimateId,
                            'ghlInvoiceId' => $ghlInvoiceId,
                            'xeroInvoiceId' => $existingXeroInvoiceId,
                        ]);
                        delete_transient($lockKey);
                        return;
                    }
                }
                
                // Store error
                $invoiceMeta['xeroSync'] = [
                    'status' => 'failed',
                    'attemptedAt' => current_time('mysql'),
                    'error' => $errorMessage,
                    'retryCount' => ($xeroSync['retryCount'] ?? 0) + 1,
                ];
                $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
                
                $this->logger->error('Xero auto-sync failed', [
                    'estimateId' => $estimateId,
                    'ghlInvoiceId' => $ghlInvoiceId,
                    'error' => $errorMessage,
                    'errorCode' => $errorCode,
                ]);
                delete_transient($lockKey);
                return;
            }
            
            // Success - store Xero invoice ID
            $invoiceMeta['xeroInvoiceId'] = $xeroResult['invoiceId'];
            $invoiceMeta['xeroInvoiceNumber'] = $xeroResult['invoiceNumber'];
            $invoiceMeta['xeroSync'] = [
                'status' => 'success',
                'attemptedAt' => current_time('mysql'),
                'error' => null,
                'retryCount' => ($xeroSync['retryCount'] ?? 0),
            ];
            $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
            
            $this->logger->info('Xero auto-sync succeeded', [
                'estimateId' => $estimateId,
                'ghlInvoiceId' => $ghlInvoiceId,
                'xeroInvoiceId' => $xeroResult['invoiceId'],
                'xeroInvoiceNumber' => $xeroResult['invoiceNumber'],
            ]);
            
        } catch (\Exception $e) {
            // Catch any unexpected errors
            $meta = $this->getMeta($estimateId);
            $invoiceMeta = $meta['invoice'] ?? [];
            $xeroSync = $invoiceMeta['xeroSync'] ?? [];
            
            $invoiceMeta['xeroSync'] = [
                'status' => 'failed',
                'attemptedAt' => current_time('mysql'),
                'error' => 'Unexpected error: ' . $e->getMessage(),
                'retryCount' => ($xeroSync['retryCount'] ?? 0) + 1,
            ];
            $this->updateMeta($estimateId, ['invoice' => $invoiceMeta]);
            
            $this->logger->error('Xero auto-sync failed with exception', [
                'estimateId' => $estimateId,
                'ghlInvoiceId' => $ghlInvoiceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        } finally {
            // Always release lock
            delete_transient($lockKey);
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

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'invoiceUrl' => $invoiceUrl,
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderAcceptanceEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? __('Thank you for accepting your estimate', 'cheapalarms');
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Acceptance email template returned empty body, using fallback');
                    $subject = __('Thank you for accepting your estimate', 'cheapalarms');
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
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render acceptance email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = __('Thank you for accepting your estimate', 'cheapalarms');
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
            }

            // Send via GHL instead of wp_mail
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send acceptance email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for acceptance email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
            $this->logger->info('Acceptance confirmation email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'hasInvoice' => !empty($invoiceUrl),
                'variation' => $variation,
            ]);
        } catch (\Exception $e) {
            // Don't fail acceptance if email fails
            $this->logger->error('Failed to send acceptance confirmation email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send booking confirmation email to customer via GHL
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $booking Booking data
     */
    private function sendBookingConfirmationEmail(string $estimateId, string $locationId, array $booking): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for booking email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for booking confirmation', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);
            
            // Format booking date
            $scheduledDate = $booking['scheduledDate'] ?? '';
            $scheduledTime = $booking['scheduledTime'] ?? '';
            $notes = $booking['notes'] ?? '';

            // Get payment info if invoice exists
            $meta = $this->getMeta($estimateId);
            $invoice = $meta['invoice'] ?? null;
            $invoiceUrl = null;
            if ($invoice) {
                // Check for new nested structure first
                if (isset($invoice['ghl']['url'])) {
                    $invoiceUrl = $invoice['ghl']['url'];
                } elseif (isset($invoice['url'])) {
                    $invoiceUrl = $invoice['url'];
                }
            }

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'scheduledDate' => $scheduledDate,
                    'scheduledTime' => $scheduledTime,
                    'notes' => $notes,
                    'invoiceUrl' => $invoiceUrl,
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderBookingEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? __('Your installation has been scheduled', 'cheapalarms');
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Booking email template returned empty body, using fallback');
                    $subject = __('Your installation has been scheduled', 'cheapalarms');
                    $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p>' . esc_html(__('Great news! Your installation has been scheduled.', 'cheapalarms')) . '</p>';
                    $formattedDate = '';
                    if ($scheduledDate) {
                        try {
                            $dateObj = new \DateTime($scheduledDate);
                            $formattedDate = $dateObj->format('l, F j, Y');
                        } catch (\Exception $e) {
                            $formattedDate = $scheduledDate;
                        }
                    }
                    $formattedTime = '';
                    if ($scheduledTime) {
                        try {
                            $timeObj = \DateTime::createFromFormat('H:i', $scheduledTime);
                            if ($timeObj) {
                                $formattedTime = $timeObj->format('g:i A');
                            } else {
                                $formattedTime = $scheduledTime;
                            }
                        } catch (\Exception $e) {
                            $formattedTime = $scheduledTime;
                        }
                    }
                    $body .= '<div style="background-color: #f0f9ff; border-left: 4px solid #c95375; padding: 16px; margin: 20px 0;">';
                    $body .= '<p style="margin: 0 0 8px 0;"><strong>' . esc_html(__('Installation Details:', 'cheapalarms')) . '</strong></p>';
                    if ($formattedDate) {
                        $body .= '<p style="margin: 4px 0;">📅 <strong>' . esc_html(__('Date:', 'cheapalarms')) . '</strong> ' . esc_html($formattedDate) . '</p>';
                    }
                    if ($formattedTime) {
                        $body .= '<p style="margin: 4px 0;">🕐 <strong>' . esc_html(__('Time:', 'cheapalarms')) . '</strong> ' . esc_html($formattedTime) . '</p>';
                    }
                    if ($notes) {
                        $body .= '<p style="margin: 4px 0;">📝 <strong>' . esc_html(__('Notes:', 'cheapalarms')) . '</strong> ' . esc_html($notes) . '</p>';
                    }
                    $body .= '</div>';
                    if ($invoiceUrl) {
                        $body .= '<p>' . esc_html(__('Next step: Complete your payment to finalize everything.', 'cheapalarms')) . '</p>';
                        $body .= '<p><a href="' . esc_url($invoiceUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Complete Payment', 'cheapalarms')) . '</a></p>';
                    } else {
                        $body .= '<p>' . esc_html(__('You can complete your payment and view all details in your portal:', 'cheapalarms')) . '</p>';
                        $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                    }
                    $body .= '<p>' . esc_html(__('If you need to reschedule or have any questions, please contact us.', 'cheapalarms')) . '</p>';
                    $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render booking email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = __('Your installation has been scheduled', 'cheapalarms');
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p>' . esc_html(__('Great news! Your installation has been scheduled.', 'cheapalarms')) . '</p>';
                $formattedDate = '';
                if ($scheduledDate) {
                    try {
                        $dateObj = new \DateTime($scheduledDate);
                        $formattedDate = $dateObj->format('l, F j, Y');
                    } catch (\Exception $e) {
                        $formattedDate = $scheduledDate;
                    }
                }
                $formattedTime = '';
                if ($scheduledTime) {
                    try {
                        $timeObj = \DateTime::createFromFormat('H:i', $scheduledTime);
                        if ($timeObj) {
                            $formattedTime = $timeObj->format('g:i A');
                        } else {
                            $formattedTime = $scheduledTime;
                        }
                    } catch (\Exception $e) {
                        $formattedTime = $scheduledTime;
                    }
                }
                $body .= '<div style="background-color: #f0f9ff; border-left: 4px solid #c95375; padding: 16px; margin: 20px 0;">';
                $body .= '<p style="margin: 0 0 8px 0;"><strong>' . esc_html(__('Installation Details:', 'cheapalarms')) . '</strong></p>';
                if ($formattedDate) {
                    $body .= '<p style="margin: 4px 0;">📅 <strong>' . esc_html(__('Date:', 'cheapalarms')) . '</strong> ' . esc_html($formattedDate) . '</p>';
                }
                if ($formattedTime) {
                    $body .= '<p style="margin: 4px 0;">🕐 <strong>' . esc_html(__('Time:', 'cheapalarms')) . '</strong> ' . esc_html($formattedTime) . '</p>';
                }
                if ($notes) {
                    $body .= '<p style="margin: 4px 0;">📝 <strong>' . esc_html(__('Notes:', 'cheapalarms')) . '</strong> ' . esc_html($notes) . '</p>';
                }
                $body .= '</div>';
                if ($invoiceUrl) {
                    $body .= '<p>' . esc_html(__('Next step: Complete your payment to finalize everything.', 'cheapalarms')) . '</p>';
                    $body .= '<p><a href="' . esc_url($invoiceUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Complete Payment', 'cheapalarms')) . '</a></p>';
                } else {
                    $body .= '<p>' . esc_html(__('You can complete your payment and view all details in your portal:', 'cheapalarms')) . '</p>';
                    $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                }
                $body .= '<p>' . esc_html(__('If you need to reschedule or have any questions, please contact us.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send booking email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for booking email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'standard') : 'standard';
            $this->logger->info('Booking confirmation email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'scheduledDate' => $scheduledDate,
                'scheduledTime' => $scheduledTime,
                'variation' => $variation,
            ]);
        } catch (\Exception $e) {
            // Don't fail booking if email fails
            $this->logger->error('Failed to send booking confirmation email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send payment confirmation email to customer via GHL
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $payment Payment data
     */
    private function sendPaymentConfirmationEmail(string $estimateId, string $locationId, array $payment): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for payment email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for payment confirmation', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);
            
            // Format payment amount
            $amount = $payment['amount'] ?? 0;
            $currency = 'AUD';
            $formattedAmount = number_format((float)$amount, 2);
            
            // Format payment date
            $paidAt = $payment['paidAt'] ?? current_time('mysql');
            $formattedDate = '';
            if ($paidAt) {
                try {
                    $dateObj = new \DateTime($paidAt);
                    $formattedDate = $dateObj->format('l, F j, Y \a\t g:i A'); // e.g., "Monday, December 3, 2024 at 2:30 PM"
                } catch (\Exception $e) {
                    $formattedDate = $paidAt;
                }
            }
            
            // Get booking details if available
            $meta = $this->getMeta($estimateId);
            $booking = $meta['booking'] ?? null;
            $bookingDate = '';
            if ($booking && isset($booking['scheduledDate'])) {
                try {
                    $dateObj = new \DateTime($booking['scheduledDate']);
                    $bookingDate = $dateObj->format('l, F j, Y');
                } catch (\Exception $e) {
                    $bookingDate = $booking['scheduledDate'];
                }
            }

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'paymentAmount' => $amount,
                    'currency' => $currency,
                    'transactionId' => $payment['transactionId'] ?? '',
                    'paidAt' => $paidAt,
                    'bookingDate' => $booking ? ($booking['scheduledDate'] ?? '') : '',
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderPaymentEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? __('Payment confirmed - Thank you!', 'cheapalarms');
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Payment email template returned empty body, using fallback');
                    $subject = __('Payment confirmed - Thank you!', 'cheapalarms');
                    $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p>' . esc_html(__('Your payment has been successfully processed!', 'cheapalarms')) . '</p>';
                    $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0;">';
                    $body .= '<p style="margin: 0 0 8px 0;"><strong>' . esc_html(__('Payment Details:', 'cheapalarms')) . '</strong></p>';
                    $body .= '<p style="margin: 4px 0;">💰 <strong>' . esc_html(__('Amount:', 'cheapalarms')) . '</strong> ' . esc_html($currency . ' $' . $formattedAmount) . '</p>';
                    if ($payment['transactionId'] ?? null) {
                        $body .= '<p style="margin: 4px 0;">📄 <strong>' . esc_html(__('Transaction ID:', 'cheapalarms')) . '</strong> ' . esc_html($payment['transactionId']) . '</p>';
                    }
                    if ($formattedDate) {
                        $body .= '<p style="margin: 4px 0;">✅ <strong>' . esc_html(__('Paid on:', 'cheapalarms')) . '</strong> ' . esc_html($formattedDate) . '</p>';
                    }
                    $body .= '</div>';
                    if ($bookingDate) {
                        $body .= '<p>' . esc_html(sprintf(
                            __('Your installation is confirmed for %s.', 'cheapalarms'),
                            $bookingDate
                        )) . '</p>';
                    } else {
                        $body .= '<p>' . esc_html(__('Your installation is confirmed.', 'cheapalarms')) . '</p>';
                    }
                    $body .= '<p>' . esc_html(__('We\'ll be in touch soon with installation details and any final preparations needed.', 'cheapalarms')) . '</p>';
                    $body .= '<p>' . esc_html(__('You can view all details and track progress in your portal:', 'cheapalarms')) . '</p>';
                    $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                    $body .= '<p>' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                    $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render payment email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = __('Payment confirmed - Thank you!', 'cheapalarms');
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p>' . esc_html(__('Your payment has been successfully processed!', 'cheapalarms')) . '</p>';
                $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0;">';
                $body .= '<p style="margin: 0 0 8px 0;"><strong>' . esc_html(__('Payment Details:', 'cheapalarms')) . '</strong></p>';
                $body .= '<p style="margin: 4px 0;">💰 <strong>' . esc_html(__('Amount:', 'cheapalarms')) . '</strong> ' . esc_html($currency . ' $' . $formattedAmount) . '</p>';
                if ($payment['transactionId'] ?? null) {
                    $body .= '<p style="margin: 4px 0;">📄 <strong>' . esc_html(__('Transaction ID:', 'cheapalarms')) . '</strong> ' . esc_html($payment['transactionId']) . '</p>';
                }
                if ($formattedDate) {
                    $body .= '<p style="margin: 4px 0;">✅ <strong>' . esc_html(__('Paid on:', 'cheapalarms')) . '</strong> ' . esc_html($formattedDate) . '</p>';
                }
                $body .= '</div>';
                if ($bookingDate) {
                    $body .= '<p>' . esc_html(sprintf(
                        __('Your installation is confirmed for %s.', 'cheapalarms'),
                        $bookingDate
                    )) . '</p>';
                } else {
                    $body .= '<p>' . esc_html(__('Your installation is confirmed.', 'cheapalarms')) . '</p>';
                }
                $body .= '<p>' . esc_html(__('We\'ll be in touch soon with installation details and any final preparations needed.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('You can view all details and track progress in your portal:', 'cheapalarms')) . '</p>';
                $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                $body .= '<p>' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send payment email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for payment email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'standard') : 'standard';
            $this->logger->info('Payment confirmation email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'amount' => $amount,
                'variation' => $variation,
            ]);
        } catch (\Exception $e) {
            // Don't fail payment if email fails
            $this->logger->error('Failed to send payment confirmation email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Complete review for an estimate
     * Transitions workflow from "under_review" to "ready_to_accept"
     * Sends notification email to customer
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $options Additional options
     * @return array|WP_Error
     */
    public function completeReview(string $estimateId, string $locationId = '', array $options = []): array|WP_Error
    {
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        $meta = $this->getMeta($estimateId);
        $workflow = $meta['workflow'] ?? [];
        $currentStatus = $workflow['status'] ?? 'requested';

        // Validate that estimate is in "under_review" status (NEW: changed from "reviewing")
        if ($currentStatus !== 'under_review') {
            return new WP_Error(
                'invalid_status',
                sprintf(
                    __('Cannot complete review. Estimate is in "%s" status, expected "under_review".', 'cheapalarms'),
                    $currentStatus
                ),
                ['status' => 400, 'currentStatus' => $currentStatus]
            );
        }
        
        // Validate that review was requested
        $quote = $meta['quote'] ?? [];
        if (empty($quote['approval_requested'])) {
            return new WP_Error(
                'review_not_requested',
                __('Cannot complete review. Customer has not requested review yet.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Validate photos if required
        $photos = $meta['photos'] ?? [];
        if (!empty($quote['photos_required'])) {
            // If photos required, validate they were submitted
            if (($photos['submission_status'] ?? '') !== 'submitted') {
                return new WP_Error(
                    'photos_not_submitted',
                    __('Cannot complete review. Photos must be submitted first.', 'cheapalarms'),
                    ['status' => 400]
                );
            }
        }

        // Transition workflow from "under_review" to "ready_to_accept" (NEW: changed from "reviewed")
        $workflow['status'] = 'ready_to_accept';
        $workflow['currentStep'] = 2; // Still step 2 (Review step)
        
        // Enable acceptance
        $quote['acceptance_enabled'] = true;
        $quote['enabled_at'] = current_time('mysql');
        $quote['enabled_by'] = get_current_user_id() ?: 1;
        
        // Mark photos as reviewed (if required)
        if (!empty($quote['photos_required'])) {
            $photos['reviewed'] = true;
            $photos['reviewed_at'] = current_time('mysql');
            $photos['reviewed_by'] = get_current_user_id() ?: 1;
        }
        
        // Update reviewedAt timestamp if not already set
        if (empty($workflow['reviewedAt'])) {
            $workflow['reviewedAt'] = current_time('mysql');
        }
        
        // Preserve existing timestamps
        if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
            $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
        }

        // Update meta
        $updateResult = $this->updateMeta($estimateId, [
            'workflow' => $workflow,
            'quote' => $quote,
            'photos' => $photos,
        ]);

        if (!$updateResult) {
            return new WP_Error(
                'update_failed',
                __('Failed to update workflow status.', 'cheapalarms'),
                ['status' => 500]
            );
        }

        $this->logger->info('Review completed successfully', [
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'reviewedAt' => $workflow['reviewedAt'],
        ]);

        // Send review completion email (non-blocking)
        if ($locationId) {
            $this->sendReviewCompletionEmail($estimateId, $locationId, $options);
        }

        return [
            'ok' => true,
            'workflow' => $workflow,
            'reviewedAt' => $workflow['reviewedAt'],
            'quote' => $quote,
            'message' => __('Review completed. Acceptance has been enabled.', 'cheapalarms'),
        ];
    }

    /**
     * Request changes to photos (admin action)
     * Keeps workflow in 'under_review' status, marks photos as reviewed but doesn't enable acceptance
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param string $note Optional note for customer
     * @return array|WP_Error
     */
    public function requestChanges(string $estimateId, string $locationId = '', string $note = ''): array|WP_Error
    {
        if (!$estimateId) {
            return new WP_Error('bad_request', __('estimateId required', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        $meta = $this->getMeta($estimateId);
        $workflow = $meta['workflow'] ?? [];
        $quote = $meta['quote'] ?? [];
        $photos = $meta['photos'] ?? [];
        
        // Validate workflow status
        if (($workflow['status'] ?? null) !== 'under_review') {
            return new WP_Error(
                'invalid_status',
                sprintf(
                    __('Cannot request changes. Estimate is in "%s" status, expected "under_review".', 'cheapalarms'),
                    $workflow['status'] ?? 'unknown'
                ),
                ['status' => 400]
            );
        }
        
        // Validate review was requested
        if (empty($quote['approval_requested'])) {
            return new WP_Error(
                'review_not_requested',
                __('Cannot request changes. Customer has not requested review yet.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Validate photos were submitted (if required)
        if (!empty($quote['photos_required'])) {
            if (($photos['submission_status'] ?? '') !== 'submitted') {
                return new WP_Error(
                    'photos_not_submitted',
                    __('Cannot request changes. Photos must be submitted first.', 'cheapalarms'),
                    ['status' => 400]
                );
            }
        }
        
        // Validate acceptance not already enabled
        if (!empty($quote['acceptance_enabled'])) {
            return new WP_Error(
                'acceptance_already_enabled',
                __('Cannot request changes. Acceptance has already been enabled.', 'cheapalarms'),
                ['status' => 400]
            );
        }
        
        // Clear submission status to allow resubmission
        // Reset reviewed flag so new submission needs to be reviewed
        if (!empty($quote['photos_required'])) {
            $photos['submission_status'] = null;
            $photos['submitted_at'] = null;
            $photos['reviewed'] = false;
            $photos['reviewed_at'] = null;
            $photos['reviewed_by'] = null;
        }
        
        // Reset approval_requested so customer can request review again after resubmission
        $quote['approval_requested'] = false;
        
        // Transition workflow back to 'sent' so customer can request review again after resubmission
        $workflow['status'] = 'sent';
        $workflow['reviewedAt'] = current_time('mysql');
        
        // Store note if provided
        if ($note) {
            $quote['change_request_note'] = sanitize_text_field($note);
            $quote['change_requested_at'] = current_time('mysql');
            $quote['change_requested_by'] = get_current_user_id() ?: 1;
        }
        
        // Update meta
        $updateResult = $this->updateMeta($estimateId, [
            'workflow' => $workflow,
            'quote' => $quote,
            'photos' => $photos,
        ]);
        
        if (!$updateResult) {
            return new WP_Error(
                'update_failed',
                __('Failed to update workflow status.', 'cheapalarms'),
                ['status' => 500]
            );
        }
        
        $this->logger->info('Changes requested', [
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'note' => $note ? 'provided' : 'not provided',
        ]);
        
        // Send notification email to customer
        if ($locationId) {
            $this->sendChangesRequestedEmail($estimateId, $locationId, $quote, $note);
        }
        
        return [
            'ok' => true,
            'message' => __('Changes requested. Customer can resubmit photos.', 'cheapalarms'),
            'workflow' => $workflow,
        ];
    }

    /**
     * Send changes requested email to customer
     * Notifies customer when admin requests changes to their photos
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array $quote Quote data (contains change_request_note if provided)
     * @param string $note Admin's note (if provided)
     * @return void
     */
    private function sendChangesRequestedEmail(string $estimateId, string $locationId, array $quote, string $note = ''): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for changes requested email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for changes requested email', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);
            
            // Get admin's note (from parameter or stored in quote meta)
            $adminNote = $note ?: ($quote['change_request_note'] ?? '');
            $hasNote = !empty($adminNote);
            $photosRequired = !empty($quote['photos_required']);

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'adminNote' => $adminNote,
                    'photosRequired' => $photosRequired,
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderChangesRequestedEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? sprintf(__('Update needed for Estimate #%s', 'cheapalarms'), $estimateNumber);
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Changes requested email template returned empty body, using fallback');
                    $subject = sprintf(__('Update needed for Estimate #%s', 'cheapalarms'), $estimateNumber);
                    $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p>' . esc_html(__('We\'ve reviewed your estimate and need a few updates before we can proceed.', 'cheapalarms')) . '</p>';
                    if ($photosRequired) {
                        $body .= '<p>' . esc_html(__('We need some additional or updated photos of your installation area.', 'cheapalarms')) . '</p>';
                    } else {
                        $body .= '<p>' . esc_html(__('We need some additional information to finalize your estimate.', 'cheapalarms')) . '</p>';
                    }
                    if ($hasNote) {
                        $body .= '<div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin: 20px 0; border-radius: 4px;">';
                        $body .= '<p style="margin: 0 0 8px 0; font-weight: bold; color: #92400e;">' . esc_html(__('Note from our team:', 'cheapalarms')) . '</p>';
                        $body .= '<p style="margin: 0; color: #78350f;">' . nl2br(esc_html($adminNote)) . '</p>';
                        $body .= '</div>';
                    }
                    $body .= '<p>' . esc_html(__('What you need to do:', 'cheapalarms')) . '</p>';
                    $body .= '<ul style="margin: 16px 0; padding-left: 24px;">';
                    if ($photosRequired) {
                        $body .= '<li>' . esc_html(__('Review the note above for specific photo requirements', 'cheapalarms')) . '</li>';
                        $body .= '<li>' . esc_html(__('Upload the additional or updated photos in your portal', 'cheapalarms')) . '</li>';
                        $body .= '<li>' . esc_html(__('Submit your photos for review again', 'cheapalarms')) . '</li>';
                    } else {
                        $body .= '<li>' . esc_html(__('Review the note above for specific requirements', 'cheapalarms')) . '</li>';
                        $body .= '<li>' . esc_html(__('Update your information in the portal', 'cheapalarms')) . '</li>';
                        $body .= '<li>' . esc_html(__('Request a review again when ready', 'cheapalarms')) . '</li>';
                    }
                    $body .= '</ul>';
                    $body .= '<p>' . esc_html(__('You can access your portal and make the updates here:', 'cheapalarms')) . '</p>';
                    $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                    $body .= '<p>' . esc_html(__('If you have any questions or need clarification, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                    $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render changes requested email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = sprintf(__('Update needed for Estimate #%s', 'cheapalarms'), $estimateNumber);
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p>' . esc_html(__('We\'ve reviewed your estimate and need a few updates before we can proceed.', 'cheapalarms')) . '</p>';
                if ($photosRequired) {
                    $body .= '<p>' . esc_html(__('We need some additional or updated photos of your installation area.', 'cheapalarms')) . '</p>';
                } else {
                    $body .= '<p>' . esc_html(__('We need some additional information to finalize your estimate.', 'cheapalarms')) . '</p>';
                }
                if ($hasNote) {
                    $body .= '<div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin: 20px 0; border-radius: 4px;">';
                    $body .= '<p style="margin: 0 0 8px 0; font-weight: bold; color: #92400e;">' . esc_html(__('Note from our team:', 'cheapalarms')) . '</p>';
                    $body .= '<p style="margin: 0; color: #78350f;">' . nl2br(esc_html($adminNote)) . '</p>';
                    $body .= '</div>';
                }
                $body .= '<p>' . esc_html(__('What you need to do:', 'cheapalarms')) . '</p>';
                $body .= '<ul style="margin: 16px 0; padding-left: 24px;">';
                if ($photosRequired) {
                    $body .= '<li>' . esc_html(__('Review the note above for specific photo requirements', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Upload the additional or updated photos in your portal', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Submit your photos for review again', 'cheapalarms')) . '</li>';
                } else {
                    $body .= '<li>' . esc_html(__('Review the note above for specific requirements', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Update your information in the portal', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Request a review again when ready', 'cheapalarms')) . '</li>';
                }
                $body .= '</ul>';
                $body .= '<p>' . esc_html(__('You can access your portal and make the updates here:', 'cheapalarms')) . '</p>';
                $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('Open Your Portal', 'cheapalarms')) . '</a></p>';
                $body .= '<p>' . esc_html(__('If you have any questions or need clarification, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send changes requested email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for changes requested email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'standard') : 'standard';
            $this->logger->info('Changes requested email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'hasNote' => $hasNote,
                'photosRequired' => $photosRequired,
                'variation' => $variation,
            ]);
        } catch (\Exception $e) {
            // Don't fail request changes if email fails
            $this->logger->error('Failed to send changes requested email', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send review completion email to customer
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array<string, mixed> $options Additional options
     */
    private function sendReviewCompletionEmail(string $estimateId, string $locationId, array $options = []): void
    {
        try {
            // Get estimate to fetch contact details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for review completion email', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $email = sanitize_email($contact['email'] ?? '');
            if (empty($email)) {
                $this->logger->warning('No email address for review completion email', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $portalUrl = $this->resolvePortalUrl($estimateId);

            // Check if there's a revision (changes made during review)
            $meta = $this->getMeta($estimateId);
            $revision = $meta['revision'] ?? null;
            $hasRevision = !empty($revision);

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'hasRevision' => $hasRevision,
                    'revision' => $revision,
                    'portalUrl' => $portalUrl,
                ];

                $emailTemplate = $emailTemplateService->renderReviewCompletionEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? ($hasRevision ? __('Your estimate has been reviewed and updated', 'cheapalarms') : __('Your estimate review is complete', 'cheapalarms'));
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Review completion email template returned empty body, using fallback');
                    $subject = $hasRevision
                        ? __('Your estimate has been reviewed and updated', 'cheapalarms')
                        : __('Your estimate review is complete', 'cheapalarms');
                    $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    if ($hasRevision) {
                        $body .= '<p>' . esc_html(__('We\'ve completed reviewing your installation photos and updated your estimate accordingly.', 'cheapalarms')) . '</p>';
                        $netChange = $revision['netChange'] ?? 0;
                        $isSavings = $netChange < 0;
                        if ($isSavings) {
                            $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0;">';
                            $body .= '<p style="margin: 0; font-size: 18px; font-weight: bold; color: #10b981;">' . esc_html(__('🎉 Great News!', 'cheapalarms')) . '</p>';
                            $body .= '<p style="margin: 8px 0 0 0;">' . esc_html(sprintf(
                                __('You save %s!', 'cheapalarms'),
                                '$' . number_format(abs($netChange), 2)
                            )) . '</p>';
                            $body .= '</div>';
                        } else if ($netChange > 0) {
                            $body .= '<div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; margin: 20px 0;">';
                            $body .= '<p style="margin: 0;">' . esc_html(sprintf(
                                __('Your estimate has been updated. Additional amount: %s', 'cheapalarms'),
                                '$' . number_format($netChange, 2)
                            )) . '</p>';
                            $body .= '</div>';
                        }
                    } else {
                        $body .= '<p>' . esc_html(__('We\'ve completed reviewing your installation photos. Your estimate is ready for acceptance!', 'cheapalarms')) . '</p>';
                    }
                    $body .= '<p>' . esc_html(__('Next steps:', 'cheapalarms')) . '</p>';
                    $body .= '<ul style="margin: 16px 0; padding-left: 24px;">';
                    $body .= '<li>' . esc_html(__('Review the updated estimate details', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Accept the estimate when ready', 'cheapalarms')) . '</li>';
                    $body .= '<li>' . esc_html(__('Schedule your installation', 'cheapalarms')) . '</li>';
                    $body .= '</ul>';
                    $body .= '<p>' . esc_html(__('View your estimate and all details in your portal:', 'cheapalarms')) . '</p>';
                    $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('View Updated Estimate', 'cheapalarms')) . '</a></p>';
                    $body .= '<p>' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                    $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render review completion email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = $hasRevision
                    ? __('Your estimate has been reviewed and updated', 'cheapalarms')
                    : __('Your estimate review is complete', 'cheapalarms');
                $body = '<p>' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                if ($hasRevision) {
                    $body .= '<p>' . esc_html(__('We\'ve completed reviewing your installation photos and updated your estimate accordingly.', 'cheapalarms')) . '</p>';
                    $netChange = $revision['netChange'] ?? 0;
                    $isSavings = $netChange < 0;
                    if ($isSavings) {
                        $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0;">';
                        $body .= '<p style="margin: 0; font-size: 18px; font-weight: bold; color: #10b981;">' . esc_html(__('🎉 Great News!', 'cheapalarms')) . '</p>';
                        $body .= '<p style="margin: 8px 0 0 0;">' . esc_html(sprintf(
                            __('You save %s!', 'cheapalarms'),
                            '$' . number_format(abs($netChange), 2)
                        )) . '</p>';
                        $body .= '</div>';
                    } else if ($netChange > 0) {
                        $body .= '<div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; margin: 20px 0;">';
                        $body .= '<p style="margin: 0;">' . esc_html(sprintf(
                            __('Your estimate has been updated. Additional amount: %s', 'cheapalarms'),
                            '$' . number_format($netChange, 2)
                        )) . '</p>';
                        $body .= '</div>';
                    }
                } else {
                    $body .= '<p>' . esc_html(__('We\'ve completed reviewing your installation photos. Your estimate is ready for acceptance!', 'cheapalarms')) . '</p>';
                }
                $body .= '<p>' . esc_html(__('Next steps:', 'cheapalarms')) . '</p>';
                $body .= '<ul style="margin: 16px 0; padding-left: 24px;">';
                $body .= '<li>' . esc_html(__('Review the updated estimate details', 'cheapalarms')) . '</li>';
                $body .= '<li>' . esc_html(__('Accept the estimate when ready', 'cheapalarms')) . '</li>';
                $body .= '<li>' . esc_html(__('Schedule your installation', 'cheapalarms')) . '</li>';
                $body .= '</ul>';
                $body .= '<p>' . esc_html(__('View your estimate and all details in your portal:', 'cheapalarms')) . '</p>';
                $body .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0;">' . esc_html(__('View Updated Estimate', 'cheapalarms')) . '</a></p>';
                $body .= '<p>' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
                $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send review completion email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for review completion email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'standard') : 'standard';
            $this->logger->info('Review completion email sent via GHL', [
                'estimateId' => $estimateId,
                'contactId' => $contactId,
                'sent' => $sent,
                'hasRevision' => $hasRevision,
                'variation' => $variation,
            ]);
        } catch (\Exception $e) {
            // Don't fail review completion if email fails
            $this->logger->error('Failed to send review completion email', [
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
     * Send review request notification to admin
     * Notifies admin when customer requests review of their estimate
     * 
     * @param string $estimateId Estimate ID
     * @param string $locationId Location ID
     * @param array $quote Quote data
     * @param array $photos Photos data
     * @return void
     */
    private function sendReviewRequestNotificationToAdmin(string $estimateId, string $locationId, array $quote, array $photos): void
    {
        try {
            // Get estimate to fetch customer details
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);

            if (is_wp_error($estimate)) {
                $this->logger->warning('Could not fetch estimate for admin review notification', [
                    'estimateId' => $estimateId,
                    'error' => $estimate->get_error_message(),
                ]);
                return;
            }

            // Get admin email
            $adminEmail = get_option('admin_email');
            if (empty($adminEmail)) {
                $this->logger->warning('No admin email configured for review request notification', [
                    'estimateId' => $estimateId,
                ]);
                return;
            }

            $contact = $estimate['contact'] ?? [];
            $customerName = sanitize_text_field($contact['name'] ?? $contact['firstName'] ?? 'Customer');
            $estimateNumber = sanitize_text_field($estimate['estimateNumber'] ?? $estimateId);
            $photosRequired = !empty($quote['photos_required']);
            $photosUploaded = $photos['uploaded'] ?? 0;
            $photosSubmitted = ($photos['submission_status'] ?? '') === 'submitted';
            
            // Admin dashboard URL (pointing to Next.js frontend)
            $adminUrl = $this->config->getFrontendUrl() . '/admin/estimates/' . $estimateId;

            $subject = sprintf('[CheapAlarms] Review Requested for Estimate #%s', $estimateNumber);
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $body = '<h2>🔍 Review Requested</h2>';
            $body .= '<p><strong>Customer:</strong> ' . esc_html($customerName) . '</p>';
            $body .= '<p><strong>Estimate:</strong> #' . esc_html($estimateNumber) . '</p>';
            $body .= '<p><strong>Requested:</strong> ' . current_time('F j, Y g:i A') . '</p>';
            
            if ($photosRequired) {
                $body .= '<hr>';
                $body .= '<p><strong>Photos Status:</strong></p>';
                $body .= '<ul>';
                $body .= '<li>Photos required: Yes</li>';
                $body .= '<li>Photos uploaded: ' . $photosUploaded . '</li>';
                $body .= '<li>Photos submitted: ' . ($photosSubmitted ? 'Yes' : 'No') . '</li>';
                $body .= '</ul>';
                
                if ($photosSubmitted) {
                    $body .= '<p style="color: #1EA6DF; font-weight: bold;">✓ Customer has submitted photos for review</p>';
                } else {
                    $body .= '<p style="color: #c95375; font-weight: bold;">⚠ Photos uploaded but not yet submitted</p>';
                }
            } else {
                $body .= '<p><strong>Photos required:</strong> No</p>';
            }
            
            $body .= '<hr>';
            $body .= '<p>The customer has requested a review of their estimate. Please:</p>';
            $body .= '<ol>';
            if ($photosRequired && $photosSubmitted) {
                $body .= '<li>Review all submitted photos in the admin panel</li>';
                $body .= '<li>Verify pricing is accurate (adjust estimate if needed)</li>';
                $body .= '<li>Approve photos and enable acceptance, OR request changes if needed</li>';
            } else {
                $body .= '<li>Review the estimate details</li>';
                $body .= '<li>Verify pricing is accurate (adjust estimate if needed)</li>';
                $body .= '<li>Enable acceptance for the customer</li>';
            }
            $body .= '</ol>';
            $body .= '<p><a href="' . esc_url($adminUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #1EA6DF; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">Review Estimate in Admin Panel</a></p>';
            $body .= '<hr>';
            $body .= '<p style="color: #666; font-size: 12px;">This is an automated notification from CheapAlarms Customer Portal.</p>';

            $sent = wp_mail($adminEmail, $subject, $body, $headers);

            if ($sent) {
                $this->logger->info('Admin review request notification sent', [
                    'estimateId' => $estimateId,
                    'photosRequired' => $photosRequired,
                    'photosUploaded' => $photosUploaded,
                    'photosSubmitted' => $photosSubmitted,
                    'adminEmail' => $adminEmail,
                ]);
            } else {
                $this->logger->warning('Failed to send admin review request notification', [
                    'estimateId' => $estimateId,
                    'adminEmail' => $adminEmail,
                ]);
            }

        } catch (\Exception $e) {
            // Don't fail review request if email fails
            $this->logger->error('Exception sending admin review notification', [
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
     * Auto-transition workflow for legacy statuses (backward compatibility)
     * Called after estimate update when revision data is provided
     * NOTE: This method handles legacy 'reviewing' and 'reviewed' statuses
     * 
     * @param string $estimateId
     * @return bool True if transition occurred, false otherwise
     */
    public function autoTransitionToReviewed(string $estimateId): bool
    {
        $meta = $this->getMeta($estimateId);
        $workflow = $meta['workflow'] ?? [];
        $photos = $meta['photos'] ?? [];
        $quote = $meta['quote'] ?? [];
        $transitioned = false;
        
        // Legacy: If workflow is "reviewing" (old status), transition to "under_review" (new status)
        if (($workflow['status'] ?? '') === 'reviewing') {
            $workflow['status'] = 'under_review';
            $workflow['currentStep'] = 2;
            $transitioned = true;
        }
        
        // Legacy: If workflow is "reviewed" (old status), transition to "ready_to_accept" (new status)
        if (($workflow['status'] ?? '') === 'reviewed') {
            $workflow['status'] = 'ready_to_accept';
            $workflow['currentStep'] = 2;
            
            // Enable acceptance if not already enabled
            if (empty($quote['acceptance_enabled'])) {
                $quote['acceptance_enabled'] = true;
                $quote['enabled_at'] = current_time('mysql');
            }
            $transitioned = true;
        }
        
        if ($transitioned) {
            // Update reviewedAt timestamp if not already set
            if (empty($workflow['reviewedAt'])) {
                $workflow['reviewedAt'] = current_time('mysql');
            }
            
            // Preserve existing timestamps
            if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
                $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
            }
            
            $result = $this->updateMeta($estimateId, [
                'workflow' => $workflow,
                'quote' => $quote,
            ]);
            
            if ($result) {
                $this->logger->info('Workflow auto-transitioned from legacy status after estimate update', [
                    'estimateId' => $estimateId,
                    'reviewedAt' => $workflow['reviewedAt'],
                ]);
            }
            
            return $result;
        }
        
        return false;
    }

    /**
     * Send estimate revision notification to customer
     * Highlights savings or changes based on photo review
     * 
     * @param string $estimateId
     * @param string $locationId
     * @param array $revisionData
     * @param array|null $estimateData Optional estimate data to avoid re-fetching
     * @return void
     */
    public function sendRevisionNotification(string $estimateId, string $locationId, array $revisionData, ?array $estimateData = null): void
    {
        try {
            // Use provided estimate data if available, otherwise fetch (optimization)
            if ($estimateData !== null && is_array($estimateData)) {
                $estimate = $estimateData;
                $this->logger->info('Using provided estimate data for revision notification', [
                    'estimateId' => $estimateId,
                ]);
            } else {
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
            
            // Validate and sanitize numeric values (handle NaN/Infinity from frontend)
            $oldTotal = floatval($revisionData['oldTotal'] ?? 0);
            $newTotal = floatval($revisionData['newTotal'] ?? 0);
            $netChange = floatval($revisionData['netChange'] ?? 0);
            
            // Ensure values are finite (not NaN or Infinity)
            if (!is_finite($oldTotal)) {
                $oldTotal = 0.0;
            }
            if (!is_finite($newTotal)) {
                $newTotal = 0.0;
            }
            if (!is_finite($netChange)) {
                $netChange = 0.0;
            }
            
            $currency = $estimate['currency'] ?? 'AUD';
            $adminNote = sanitize_text_field($revisionData['adminNote'] ?? '');
            
            $isSavings = $netChange < 0;
            $isIncrease = $netChange > 0;

            // Get user ID from email
            $userId = email_exists($email);
            
            // Get user context for email personalization
            $userContext = UserContextHelper::getUserContext($userId, $email, $estimateId);

            // Render context-aware email template
            $emailTemplate = null;
            try {
                $emailTemplateService = $this->container->get(EmailTemplateService::class);
                $emailData = [
                    'customerName' => $customerName,
                    'estimateNumber' => $estimateNumber,
                    'revisionData' => [
                        'oldTotal' => $oldTotal,
                        'newTotal' => $newTotal,
                        'netChange' => $netChange,
                        'adminNote' => $adminNote,
                    ],
                    'portalUrl' => $portalUrl,
                    'currency' => $currency,
                ];

                $emailTemplate = $emailTemplateService->renderRevisionEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? ($isSavings 
                    ? sprintf(__('🎉 Great news! Your CheapAlarms estimate has been updated - Save %s %s', 'cheapalarms'), $currency, number_format(abs($netChange), 2))
                    : __('Your CheapAlarms estimate has been updated', 'cheapalarms'));
                $body = $emailTemplate['body'] ?? '';

                // Fallback if template rendering failed
                if (empty($body)) {
                    error_log('[CheapAlarms][WARNING] Revision email template returned empty body, using fallback');
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
                    if ($adminNote) {
                        $body .= '<div style="background: #f8f9fa; border-left: 4px solid ' . $boxColor . '; padding: 16px; border-radius: 8px; margin: 24px 0;">';
                        $body .= '<div style="font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 8px;">FROM YOUR INSTALLER</div>';
                        $body .= '<div style="color: #1f2937;">' . nl2br(esc_html($adminNote)) . '</div>';
                        $body .= '</div>';
                    }
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
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render revision email template: ' . $e->getMessage());
                // Fallback to simple email
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
                if ($adminNote) {
                    $body .= '<div style="background: #f8f9fa; border-left: 4px solid ' . $boxColor . '; padding: 16px; border-radius: 8px; margin: 24px 0;">';
                    $body .= '<div style="font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 8px;">FROM YOUR INSTALLER</div>';
                    $body .= '<div style="color: #1f2937;">' . nl2br(esc_html($adminNote)) . '</div>';
                    $body .= '</div>';
                }
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
            }

            // Send via GHL
            $contactId = $contact['id'] ?? null;
            $sent = false;
            
            if ($contactId) {
                $result = $this->sendEmailViaGhl($contactId, $subject, $body);
                if (is_wp_error($result)) {
                    $this->logger->error('Failed to send revision email via GHL', [
                        'estimateId' => $estimateId,
                        'contactId' => $contactId,
                        'email' => $email,
                        'error' => $result->get_error_message(),
                        'error_code' => $result->get_error_code(),
                    ]);
                    $sent = false;
                } else {
                    $sent = $result === true;
                }
            } else {
                $this->logger->warning('No GHL contact ID for revision email, cannot send via GHL', [
                    'estimateId' => $estimateId,
                    'email' => $email,
                ]);
            }

            if ($sent) {
                $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'standard') : 'standard';
                $this->logger->info('Estimate revision notification sent', [
                    'estimateId' => $estimateId,
                    'contactId' => $contactId,
                    'isSavings' => $isSavings,
                    'netChange' => $netChange,
                    'variation' => $variation,
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

    /**
     * Compute payment totals from payments array
     * 
     * @param array $payments Array of payment records
     * @param float $invoiceTotal Total invoice amount
     * @return array Computed totals
     */
    private function computePaymentTotals(array $payments, float $invoiceTotal): array
    {
        $totalPaid = 0;
        $depositPaid = false;
        $depositPaidAt = null;
        
        foreach ($payments as $p) {
            if (($p['status'] ?? '') === 'succeeded' && !($p['refunded'] ?? false)) {
                $totalPaid += (float) ($p['amount'] ?? 0);
                
                if (($p['paymentType'] ?? '') === 'deposit') {
                    $depositPaid = true;
                    $depositPaidAt = $depositPaidAt ?: ($p['paidAt'] ?? null);
                }
            }
        }
        
        $remainingBalance = max(0, $invoiceTotal - $totalPaid);
        $isFullyPaid = ($totalPaid >= $invoiceTotal);
        
        return [
            'totalPaid' => $totalPaid,
            'remainingBalance' => $remainingBalance,
            'isFullyPaid' => $isFullyPaid,
            'hasDepositPaid' => $depositPaid,
            'depositPaidAt' => $depositPaidAt,
            'status' => $isFullyPaid ? 'paid' : ($totalPaid > 0 ? 'partial' : 'pending'),
        ];
    }

    /**
     * Check if booking is available for estimate
     * 
     * Rules:
     * - If depositRequired: booking allowed only if deposit paid AND not refunded
     * - If no deposit: booking allowed if totalPaid > 0 (or your business rule)
     * 
     * @param string $estimateId
     * @return bool
     */
    public function canBook(string $estimateId): bool
    {
        $meta = $this->getMeta($estimateId);
        $payment = $meta['payment'] ?? [];
        $invoice = $meta['invoice'] ?? [];
        
        $depositRequired = $invoice['depositRequired'] ?? false;
        
        if ($depositRequired) {
            // Must have deposit paid and not refunded
            $hasDepositPaid = $payment['hasDepositPaid'] ?? false;
            if (!$hasDepositPaid) {
                return false;
            }
            
            // Check if deposit was refunded
            $depositRefunded = $this->isDepositRefunded($payment);
            if ($depositRefunded) {
                return false;
            }
            
            return true;
        }
        
        // If no deposit required, allow booking when any payment exists
        $totalPaid = $payment['totalPaid'] ?? 0;
        return $totalPaid > 0;
    }

    /**
     * Check if deposit payment was refunded
     * 
     * @param array $payment Payment meta
     * @return bool
     */
    private function isDepositRefunded(array $payment): bool
    {
        if (empty($payment['payments']) || !is_array($payment['payments'])) {
            return false;
        }
        
        foreach ($payment['payments'] as $p) {
            if (($p['paymentType'] ?? '') === 'deposit') {
                return ($p['refunded'] ?? false) === true;
            }
        }
        
        return false;
    }

    /**
     * Reconcile payment state from Stripe (source of truth)
     * 
     * Use when:
     * - Webhooks were down
     * - Suspect drift
     * - Admin needs "Fix payments state" button
     */
    public function reconcilePaymentState(string $estimateId): array|WP_Error
    {
        $meta = $this->getMeta($estimateId);
        $payment = $meta['payment'] ?? [];
        $invoiceTotal = $meta['invoice']['total'] ?? $meta['invoice']['ghl']['total'] ?? 0;
        
        if ($invoiceTotal <= 0) {
            return new WP_Error('no_invoice', __('No invoice found for reconciliation.', 'cheapalarms'), ['status' => 400]);
        }
        
        $stripeService = $this->container->get(\CheapAlarms\Plugin\Services\StripeService::class);
        $payments = $payment['payments'] ?? [];
        
        // Verify each payment intent with Stripe
        $verifiedPayments = [];
        
        foreach ($payments as $p) {
            $paymentIntentId = $p['paymentIntentId'] ?? null;
            if (empty($paymentIntentId)) {
                continue;
            }
            
            $stripeResult = $stripeService->getPaymentIntent($paymentIntentId);
            if (is_wp_error($stripeResult)) {
                $this->logger->warning('Payment intent not found in Stripe during reconciliation', [
                    'estimateId' => $estimateId,
                    'paymentIntentId' => $paymentIntentId,
                ]);
                continue;
            }
            
            $stripeStatus = $stripeResult['status'] ?? 'unknown';
            $stripeAmount = $stripeResult['amount'] ?? 0;
            
            // Update payment record with Stripe status (source of truth)
            $p['status'] = ($stripeStatus === 'succeeded') ? 'succeeded' : 'failed';
            $p['amount'] = $stripeAmount; // Use Stripe amount
            
            $verifiedPayments[] = $p;
        }
        
        // Recompute totals
        $totals = $this->computePaymentTotals($verifiedPayments, $invoiceTotal);
        
        // Update portal meta
        $this->updateMeta($estimateId, [
            'payment' => array_merge($payment, [
                'payments' => $verifiedPayments,
                'totalPaid' => $totals['totalPaid'],
                'remainingBalance' => $totals['remainingBalance'],
                'isFullyPaid' => $totals['isFullyPaid'],
                'hasDepositPaid' => $totals['hasDepositPaid'],
                'depositPaidAt' => $totals['depositPaidAt'],
                'status' => $totals['status'],
                'reconciledAt' => current_time('mysql'),
            ]),
        ]);
        
        return [
            'ok' => true,
            'totalPaid' => $totals['totalPaid'],
            'remainingBalance' => $totals['remainingBalance'],
            'isFullyPaid' => $totals['isFullyPaid'],
            'hasDepositPaid' => $totals['hasDepositPaid'],
        ];
    }
}

