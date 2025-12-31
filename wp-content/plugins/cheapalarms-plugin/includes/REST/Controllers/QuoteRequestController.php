<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\PortalService;
use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\REST\Auth\Authenticator;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

use function register_rest_route;
use function sanitize_text_field;
use function sanitize_email;
use function is_wp_error;
use function email_exists;
use function wp_create_user;
use function wp_generate_password;
use function get_user_by;
use function wp_update_user;
use function current_time;
use function update_option;
use function wp_json_encode;
use function get_user_meta;
use function update_user_meta;
use function home_url;
use function get_option;
use function trailingslashit;
use function gmdate;
use function strtotime;
use function mb_substr;
use function trim;
use function str_starts_with;
use function ltrim;
use function add_query_arg;
use function get_password_reset_key;
use function rawurlencode;
use function esc_url;
use function esc_html;
use function __;
use function get_transient;
use function set_transient;
use function delete_transient;

/**
 * Public Quote Request Controller
 * Handles public quote requests from the calculator
 */
class QuoteRequestController implements ControllerInterface
{
    private GhlClient $ghlClient;
    private EstimateService $estimateService;
    private PortalService $portalService;
    private Config $config;
    private Container $container;
    private Authenticator $authenticator;

    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->ghlClient = $container->get(GhlClient::class);
        $this->estimateService = $container->get(EstimateService::class);
        $this->portalService = $container->get(PortalService::class);
        $this->config = $container->get(Config::class);
        $this->authenticator = $container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/quote-request', [
            'methods'             => 'POST',
            'permission_callback' => '__return_true', // Public endpoint
            'callback'            => [$this, 'handleQuoteRequest'],
        ]);
    }

    /**
     * Handle public quote request from calculator
     */
    public function handleQuoteRequest(WP_REST_Request $request): WP_REST_Response
    {
        // Rate limit public quote requests to prevent abuse
        $rateCheck = $this->authenticator->enforceRateLimit('quote_request_public');
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }

        $body = $request->get_json_params();

        // Validate required fields
        $firstName = sanitize_text_field($body['firstName'] ?? '');
        $lastName = sanitize_text_field($body['lastName'] ?? '');
        $email = sanitize_email($body['email'] ?? '');
        $phone = sanitize_text_field($body['phone'] ?? '');

        if (empty($firstName) || empty($lastName) || empty($email)) {
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'Missing required fields: firstName, lastName, email',
            ], 400);
        }

        // Define lock key BEFORE using it (needed for duplicate prevention)
        $lockKey = 'ca_quote_request_lock_' . md5($email);

        // DUPLICATE PREVENTION: Check if same email recently created an estimate
        // Use email-based lock (60 seconds) to prevent duplicate quote requests
        $lockValue = get_transient($lockKey);
        
        if ($lockValue !== false) {
            // Check if lock is stale (older than 60 seconds - previous request completed/failed)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 60) {
                // Lock is stale - clear it and proceed
                delete_transient($lockKey);
            } else {
                // Lock is active - check if estimate was actually created
                $userId = email_exists($email);
                if ($userId) {
                    $recentEstimateIds = get_user_meta($userId, 'ca_estimate_ids', true);
                    if (is_array($recentEstimateIds) && !empty($recentEstimateIds)) {
                        // Check if most recent estimate was created in last 60 seconds
                        $mostRecentEstimateId = end($recentEstimateIds);
                        $metaKey = "ca_portal_meta_{$mostRecentEstimateId}";
                        $recentMeta = get_option($metaKey, '{}');
                        $meta = json_decode($recentMeta, true);
                        
                        if (is_array($meta)) {
                            $createdAt = $meta['quote']['createdAt'] ?? $meta['workflow']['createdAt'] ?? null;
                            if ($createdAt) {
                                $createdTimestamp = strtotime($createdAt);
                                $timeSinceCreation = time() - $createdTimestamp;
                                
                                if ($timeSinceCreation < 60) {
                                    // Recent estimate found - duplicate request
                                    return new WP_REST_Response([
                                        'ok' => false,
                                        'error' => 'A quote request was recently submitted for this email. Please check your inbox. If you need another quote, please wait a moment and try again.',
                                        'code' => 'duplicate_request',
                                        'retryAfter' => 60 - $timeSinceCreation,
                                    ], 429); // 429 Too Many Requests
                                }
                            }
                        }
                    }
                }
                
                // Lock is active but no recent estimate found - might be processing
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'A quote request is currently being processed for this email. Please wait a moment and check your email.',
                    'code' => 'duplicate_request',
                    'retryAfter' => 60 - $lockAge,
                ], 429);
            }
        }
        
        // Set lock with timestamp (60 second expiry)
        set_transient($lockKey, time(), 60);

        // Validate items
        $items = $body['items'] ?? [];
        if (empty($items) || !is_array($items)) {
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'Missing or invalid items array',
            ], 400);
        }
        
        // Sanitize items to match GHL expected structure
        $sanitizedItems = [];
        foreach ($items as $item) {
            $itemName = (string)($item['name'] ?? '');
            $itemAmount = (float)($item['amount'] ?? 0);
            
            // Skip items without name or with zero/negative amount
            if (empty($itemName) || $itemAmount <= 0) {
                continue;
            }
            
            $sanitizedItems[] = [
                'name'        => $itemName,
                'description' => (string)($item['description'] ?? ''),
                'currency'    => (string)($item['currency'] ?? 'AUD'),
                'amount'      => $itemAmount,
                'qty'         => (int)($item['qty'] ?? $item['quantity'] ?? 1),
                'type'        => (string)($item['type'] ?? 'one_time'),  // GHL requires this
            ];
        }
        
        // Ensure we have at least one valid item after sanitization
        if (empty($sanitizedItems)) {
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'No valid items found. Items must have name and amount > 0.',
            ], 400);
        }

        // Optional fields
        $locationId = sanitize_text_field($body['locationId'] ?? '');
        $propertyProfile = sanitize_text_field($body['propertyProfile'] ?? '');
        $address = $body['address'] ?? null;

        try {
            // Use effective location ID
            $effectiveLocationId = $locationId ?: $this->config->getLocationId();
            
            // Step 1: Create contact in GHL
            $contactPayload = [
                'firstName' => $firstName,
                'lastName' => $lastName,
                'email' => $email,
                'phone' => $phone,
                'locationId' => $effectiveLocationId,
            ];

            if ($address && is_array($address)) {
                $contactPayload['address1'] = $address['address1'] ?? '';
                $contactPayload['city'] = $address['city'] ?? '';
                $contactPayload['state'] = $address['state'] ?? '';
                $contactPayload['postalCode'] = $address['postalCode'] ?? '';
                $contactPayload['country'] = $address['country'] ?? 'AU';
            }

            // Use shorter timeout for contact creation to keep UX snappy on submit
            $contactResult = $this->ghlClient->post('/contacts/', $contactPayload, 8, $effectiveLocationId);
            
            if (is_wp_error($contactResult)) {
                // Handle duplicate contact errors safely:
                // - If duplicate is by EMAIL, reuse existing contactId (safe).
                // - If duplicate is by PHONE, DO NOT auto-merge (unsafe); return a friendly conflict.
                $errorData = $contactResult->get_error_data();
                $errorCode = $contactResult->get_error_code();

                $contactId = null;
                $matchingField = null;

                if ($errorCode === 'ghl_http_error' && isset($errorData['code']) && (int)$errorData['code'] === 400) {
                    $errorBody = $errorData['body'] ?? null;
                    if (is_string($errorBody)) {
                        $decoded = json_decode($errorBody, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $errorBody = $decoded;
                        }
                    }

                    if (is_array($errorBody)) {
                        $contactId = $errorBody['meta']['contactId'] ?? null;
                        $matchingField = $errorBody['meta']['matchingField'] ?? null;
                    }

                    // If GHL indicates phone-based duplication, don't auto-merge.
                    if (!empty($contactId) && is_string($matchingField) && strtolower($matchingField) === 'phone') {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'This phone number is already linked to another account. Please use the email you used previously, or contact support.',
                            'code' => 'phone_conflict',
                        ], 409);
                    }

                    // If GHL indicates email-based duplication, it's safe to reuse.
                    if (!empty($contactId) && is_string($matchingField) && strtolower($matchingField) === 'email') {
                        // safe path: reuse $contactId
                    } elseif (!empty($contactId) && empty($matchingField)) {
                        // Defensive: if matchingField is missing, verify by searching contacts by email (fast, no retry).
                        // Fail CLOSED: if we cannot confirm it's an email-duplicate, we return a friendly conflict.
                        // Also: prefer the contactId returned by search (stronger than trusting meta.contactId).
                        $foundByEmail = false;
                        $contactIdFromSearch = null;
                        try {
                            $search = $this->ghlClient->get('/contacts/search', [
                                'locationId' => $effectiveLocationId,
                                'query' => $email,
                            ], 5, $effectiveLocationId, 0);

                            if (is_wp_error($search)) {
                                return new WP_REST_Response([
                                    'ok' => false,
                                    'error' => 'We found an existing contact that conflicts with the details you entered. Please use the email you used previously or contact support.',
                                    'code' => 'contact_conflict',
                                ], 409);
                            }

                            $contacts = $search['contacts'] ?? $search['items'] ?? [];
                            foreach ((array)$contacts as $c) {
                                $cEmail = $c['email'] ?? '';
                                if ($cEmail && strcasecmp((string)$cEmail, (string)$email) === 0) {
                                    $foundByEmail = true;
                                    $contactIdFromSearch = $c['id'] ?? ($c['contactId'] ?? null);
                                    break;
                                }
                            }
                        } catch (\Exception $e) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'We found an existing contact that conflicts with the details you entered. Please use the email you used previously or contact support.',
                                'code' => 'contact_conflict',
                            ], 409);
                        }

                        if (!$foundByEmail) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'We found an existing contact with this email/phone combination, but couldn’t safely confirm it’s the same person. Please use the email you used previously or contact support.',
                                'code' => 'contact_conflict',
                            ], 409);
                        }

                        if (!empty($contactIdFromSearch)) {
                            $contactId = $contactIdFromSearch;
                        }
                    } elseif (!empty($contactId) && is_string($matchingField) && $matchingField !== '') {
                        // Unknown matching field - treat as conflict to avoid wrong merge.
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'We found an existing contact that conflicts with the details you entered. Please use the email you used previously or contact support.',
                            'code' => 'contact_conflict',
                        ], 409);
                    }
                }

                if (empty($contactId)) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'Failed to create contact: ' . $contactResult->get_error_message(),
                    ], 500);
                }
            } else {
                $contactId = $contactResult['contact']['id'] ?? null;
            }
            
            if (!$contactId) {
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Contact created but ID missing',
                ], 500);
            }

            // Step 2: Create estimate in GHL
            // Format phone to E.164 (GHL might require this)
            $formattedPhone = '';
            if ($phone) {
                $formattedPhone = str_starts_with($phone, '+') 
                    ? $phone 
                    : '+61' . ltrim($phone, '0');
            }
            
            $estimateData = [
                'altId' => $effectiveLocationId,
                'altType' => 'location',
                'name' => mb_substr("Quote - {$firstName} {$lastName}", 0, 40),
                'title' => 'ESTIMATE',
                'businessDetails' => [
                    'name' => 'Cheap Alarms',
                    'address' => [
                        'addressLine1' => 'Cheap Alarms Pty Ltd',
                        'city' => 'Brisbane',
                        'state' => 'QLD',
                        'postalCode' => '4000',
                        'countryCode' => 'AU',
                    ],
                ],
                'currency' => 'AUD',
                'discount' => [
                    'type' => 'percentage',
                    'value' => 0,
                ],
                'contactDetails' => [
                    'id' => $contactId,
                    'email' => $email,
                    'name' => trim("{$firstName} {$lastName}"),
                    'phoneNo' => $formattedPhone,
                    'address' => [
                        'addressLine1' => '',
                        'city' => '',
                        'state' => '',
                        'postalCode' => '',
                        'countryCode' => 'AU',
                    ],
                ],
                'issueDate' => gmdate('Y-m-d'),
                'expiryDate' => gmdate('Y-m-d', strtotime('+30 days')),
                'frequencySettings' => ['enabled' => false],
                'liveMode' => true,
                'items' => $sanitizedItems,  // Use sanitized items (5 fields only)
            ];

            // Add property profile to notes if provided
            if ($propertyProfile) {
                $estimateData['termsNotes'] = "Property Profile: {$propertyProfile}";
            }

            // Use shorter timeout, no retry, and skip the slow post-create PUT for public quote flow
            $estimateResult = $this->estimateService->createEstimate($estimateData, 8, 0, true);
            
            if (is_wp_error($estimateResult)) {
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Failed to create estimate: ' . $estimateResult->get_error_message(),
                ], 500);
            }

            // Check if result has 'ok' key
            if (!isset($estimateResult['ok']) || !$estimateResult['ok']) {
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Failed to create estimate',
                ], 500);
            }

            // Extract ID from nested response structure
            $response = $estimateResult['result'] ?? [];
            $estimateId = $response['estimate']['id'] ?? $response['id'] ?? $response['_id'] ?? null;
            $estimateNumberFromCreate = $response['estimate']['estimateNumber'] ?? $response['estimateNumber'] ?? null;
            $estimateTotalFromCreate = $response['estimate']['total'] ?? $response['total'] ?? null;
            $estimateCurrencyFromCreate = $response['estimate']['currency'] ?? $response['currency'] ?? 'AUD';
            
            if (!$estimateId) {
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Estimate created but ID missing in response',
                ], 500);
            }

            // Step 3: Create portal entry and send invitation
            // SECURITY: Generate invite token and hash it before storage
            $inviteToken = \CheapAlarms\Plugin\Services\PortalService::generateToken();
            $inviteTokenHash = \CheapAlarms\Plugin\Services\PortalService::hashInviteToken($inviteToken);
            
            // Use frontend URL (Next.js on Vercel) instead of WordPress backend URL
            $frontendUrl = $this->config->getFrontendUrl();
            $portalUrl = add_query_arg(
                [
                    'estimateId' => $estimateId,
                    'inviteToken' => $inviteToken, // Plaintext token in URL
                ],
                trailingslashit($frontendUrl) . 'portal'
            );

            // Check if user exists
            $userId = email_exists($email);
            if (!$userId) {
                // Create WordPress user
                $userId = wp_create_user($email, wp_generate_password(), $email);
                if (is_wp_error($userId)) {
                    error_log('Failed to create user: ' . $userId->get_error_message());
                    $userId = 0;
                } else {
                    // Set role
                    $user = get_user_by('id', $userId);
                    if ($user) {
                        $user->set_role('ca_customer');
                        wp_update_user([
                            'ID' => $userId,
                            'first_name' => $firstName,
                            'last_name' => $lastName,
                            'display_name' => trim("{$firstName} {$lastName}"),
                        ]);
                    }
                }
            } else {
                // Ensure existing user has ca_customer role (has ca_access_portal capability)
                $user = get_user_by('id', $userId);
                if ($user && !in_array('ca_customer', $user->roles, true)) {
                    wp_update_user(['ID' => $userId, 'role' => 'ca_customer']);
                }
            }

            // Build portal meta (will be saved after password reset generation)
            $portalMeta = [
                'account' => [
                    'inviteToken' => $inviteTokenHash, // Store hash, not plaintext
                    'portalUrl' => $portalUrl,
                    'status' => 'pending',
                    'statusLabel' => 'Invite sent',
                    'userId' => $userId ?: null,
                    'lastInviteAt' => current_time('mysql'),
                    'canResend' => true,
                    'expiresAt' => gmdate('c', current_time('timestamp') + DAY_IN_SECONDS * 7),
                    'email' => $email,
                    'locationId' => $effectiveLocationId,
                ],
                'quote' => [
                    'status' => null, // Will be set to 'sent' after auto-send
                    'statusLabel' => null,
                    'total' => null, // Will be populated when estimate is fetched
                    'approval_requested' => false, // NEW: Customer hasn't requested review yet
                ],
                'workflow' => [
                    'status' => 'requested',
                    'currentStep' => 1,
                    'requestedAt' => current_time('mysql'),
                ],
            ];

            // Attach estimate to user if user exists
            if ($userId) {
                $estimateIds = get_user_meta($userId, 'ca_estimate_ids', true);
                if (!is_array($estimateIds)) {
                    $estimateIds = [];
                }
                if (!in_array($estimateId, $estimateIds, true)) {
                    $estimateIds[] = $estimateId;
                    update_user_meta($userId, 'ca_estimate_ids', $estimateIds);
                }
                
                // Store most recent estimate ID (singular) for auto-redirect
                update_user_meta($userId, 'ca_estimate_id', $estimateId);
                
                // Store location ID mapping
                $locations = get_user_meta($userId, 'ca_estimate_locations', true);
                if (!is_array($locations)) {
                    $locations = [];
                }
                $locations[$estimateId] = $effectiveLocationId;
                update_user_meta($userId, 'ca_estimate_locations', $locations);
            }

            // Generate password reset key for new users (pointing to Next.js frontend)
            $resetUrl = null;
            if ($userId) {
                $user = get_user_by('id', $userId);
                if ($user) {
                    $key = get_password_reset_key($user);
                    if (!is_wp_error($key)) {
                        $frontendUrl = $this->config->getFrontendUrl();
                        $resetUrl = add_query_arg(
                            [
                                'key' => $key,
                                'login' => rawurlencode($user->user_login),
                                'estimateId' => $estimateId,
                            ],
                            trailingslashit($frontendUrl) . 'set-password'
                        );
                        
                        // Add reset URL to portal meta
                        $portalMeta['account']['resetUrl'] = $resetUrl;
                    }
                }
            }
            
            // Save portal meta once with all data (CRITICAL: Portal access depends on this)
            $jsonMeta = wp_json_encode($portalMeta);
            if ($jsonMeta === false) {
                error_log('[CheapAlarms][ERROR] Failed to encode portal meta JSON for estimate: ' . $estimateId);
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Failed to save portal data. Please contact support.',
                ], 500);
            }
            
            $metaSaved = update_option("ca_portal_meta_{$estimateId}", $jsonMeta);
            if (!$metaSaved) {
                error_log('[CheapAlarms][ERROR] Failed to save portal meta for estimate: ' . $estimateId);
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Failed to save portal data. Please contact support.',
                ], 500);
            }

            // Step 4: Update workflow status (skip auto-sending estimate email - we'll send consolidated quote request email below)
            // Note: sendEstimate() should only be used for manual admin resends, not for new quote requests
            // This prevents duplicate emails (estimate email + quote request email)
            try {
                // Update workflow status to 'sent' without sending email
                $stored = get_option("ca_portal_meta_{$estimateId}", '{}');
                $meta = json_decode($stored, true);
                if (is_array($meta)) {
                    // Ensure workflow and quote arrays exist
                    if (!isset($meta['workflow'])) {
                        $meta['workflow'] = [];
                    }
                    if (!isset($meta['quote'])) {
                        $meta['quote'] = [];
                    }
                    $meta['workflow']['status'] = 'sent';
                    $meta['workflow']['currentStep'] = 2;
                    $meta['quote']['status'] = 'sent';
                    $meta['quote']['statusLabel'] = 'Sent';
                    $meta['quote']['sentAt'] = current_time('mysql');
                    $meta['quote']['sendCount'] = 1;
                    $meta['quote']['approval_requested'] = false; // Ensure approval is not requested on send
                    
                    // Store estimate snapshot data for fast dashboard loading using creation response (no extra GHL call)
                    $meta['quote']['number'] = $estimateNumberFromCreate ?? $estimateId;
                    $meta['quote']['total'] = $estimateTotalFromCreate ?? 0;
                    $meta['quote']['currency'] = $estimateCurrencyFromCreate ?? 'AUD';
                    $meta['quote']['last_synced_at'] = current_time('mysql');
                    
                    update_option("ca_portal_meta_{$estimateId}", wp_json_encode($meta));
                }
            } catch (\Exception $e) {
                // Log but don't fail - estimate creation succeeded
                error_log('[CheapAlarms][WARNING] Exception updating workflow status: ' . $e->getMessage());
            }

            // Send context-aware invitation email via GHL Conversations API
            $displayName = trim("{$firstName} {$lastName}");
            
            // Get user context for email personalization
            $userContext = \CheapAlarms\Plugin\Services\UserContextHelper::getUserContext($userId, $email, $estimateId);
            
            // Get estimate number for email (use creation response, avoid extra GHL call)
            $estimateNumber = $estimateNumberFromCreate ?? $estimateId; // Fallback to estimateId
            
            // Get frontend URL for login link
            $frontendUrl = $this->config->getFrontendUrl();
            $loginUrl = trailingslashit($frontendUrl) . 'login';
            
            // Initialize emailTemplate variable (may be null if rendering fails)
            $emailTemplate = null;
            
            // Render context-aware email template
            try {
                $emailTemplateService = $this->container->get(\CheapAlarms\Plugin\Services\EmailTemplateService::class);
                $emailData = [
                    'customerName' => $displayName,
                    'estimateNumber' => $estimateNumber,
                    'portalUrl' => $portalUrl,
                    'resetUrl' => $resetUrl,
                    'loginUrl' => $loginUrl,
                ];
                
                $emailTemplate = $emailTemplateService->renderQuoteRequestEmail($userContext, $emailData);
                $subject = $emailTemplate['subject'] ?? __('Your CheapAlarms quote is ready', 'cheapalarms');
                $message = $emailTemplate['body'] ?? '';
                
                // Fallback if template rendering failed
                if (empty($message)) {
                    error_log('[CheapAlarms][WARNING] Email template returned empty body, using fallback');
                    $subject = __('Your CheapAlarms quote is ready', 'cheapalarms');
                    $greeting = sprintf(__('Hi %s,', 'cheapalarms'), esc_html($displayName));
                    $message = '<p>' . $greeting . '</p>';
                    $message .= '<p>' . esc_html(__('We have prepared your quote. Click the button below to set your password and access your estimate:', 'cheapalarms')) . '</p>';
                    if ($resetUrl) {
                        $message .= '<p><a href="' . esc_url($resetUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('Set Your Password', 'cheapalarms')) . '</a></p>';
                    }
                    if ($portalUrl) {
                        $message .= '<p style="margin-top: 16px; color: #64748b; font-size: 14px;">' . esc_html(__('or', 'cheapalarms')) . ' <a href="' . esc_url($portalUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('see your estimate as a guest', 'cheapalarms')) . '</a></p>';
                    }
                    $message .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
                }
            } catch (\Exception $e) {
                error_log('[CheapAlarms][ERROR] Failed to render email template: ' . $e->getMessage());
                // Fallback to simple email
                $subject = __('Your CheapAlarms quote is ready', 'cheapalarms');
                $greeting = sprintf(__('Hi %s,', 'cheapalarms'), esc_html($displayName));
                $message = '<p>' . $greeting . '</p>';
                $message .= '<p>' . esc_html(__('We have prepared your quote. Click the button below to set your password and access your estimate:', 'cheapalarms')) . '</p>';
                if ($resetUrl) {
                    $message .= '<p><a href="' . esc_url($resetUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('Set Your Password', 'cheapalarms')) . '</a></p>';
                }
                if ($portalUrl) {
                    $message .= '<p style="margin-top: 16px; color: #64748b; font-size: 14px;">' . esc_html(__('or', 'cheapalarms')) . ' <a href="' . esc_url($portalUrl) . '" style="color: #2fb6c9; text-decoration: underline;">' . esc_html(__('see your estimate as a guest', 'cheapalarms')) . '</a></p>';
                }
                $message .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            }
            
            // Send via GHL Conversations API
            $fromEmail = get_option('ghl_from_email', 'quotes@cheapalarms.com.au');
            
            $emailPayload = [
                'contactId' => $contactId,
                'type' => 'Email',
                'status' => 'pending',
                'subject' => $subject,
                'html' => $message,
                'emailFrom' => $fromEmail,
                'locationId' => $effectiveLocationId,
            ];
            
            $emailResult = $this->ghlClient->post('/conversations/messages', $emailPayload);
            
            $emailSent = !is_wp_error($emailResult);
            
            if ($emailSent) {
                $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
                error_log('[CheapAlarms][INFO] Quote invitation email sent via GHL to: ' . $email . ' (variation: ' . $variation . ')');
            } else {
                error_log('Failed to send GHL email to: ' . $email . ' - ' . ($emailResult instanceof WP_Error ? $emailResult->get_error_message() : 'Unknown error'));
            }

            // Success! Keep the lock for full 60 seconds to prevent duplicate submissions
            // (Don't clear it - let it expire naturally)
            
            return new WP_REST_Response([
                'ok' => true,
                'contactId' => $contactId,
                'estimateId' => $estimateId,
                'locationId' => $effectiveLocationId,
                'portalUrl' => $portalUrl,
                'emailSent' => $emailSent,
                'message' => 'Quote request submitted successfully! Check your email for the portal link.',
            ], 200);

        } catch (\Exception $e) {
            // Clear lock on error so user can retry
            delete_transient($lockKey);
            
            error_log('Quote request error: ' . $e->getMessage());
            
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'An unexpected error occurred. Please try again.',
            ], 500);
        }
    }

    /**
     * Standardized response handler
     * 
     * @param array|WP_Error $result
     * @return WP_REST_Response
     */
    private function respond($result): WP_REST_Response
    {
        if (is_wp_error($result)) {
            return $this->errorResponse($result);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        $response = new WP_REST_Response($result, 200);
        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Create standardized error response with sanitization
     *
     * @param WP_Error $error
     * @return WP_REST_Response
     */
    private function errorResponse(WP_Error $error): WP_REST_Response
    {
        $status = $error->get_error_data()['status'] ?? 500;
        $code = $error->get_error_code();
        $message = $error->get_error_message();

        $response = new WP_REST_Response([
            'ok' => false,
            'error' => $message,
            'code' => $code,
        ], $status);

        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Add security headers to response
     *
     * @param WP_REST_Response $response
     */
    private function addSecurityHeaders(WP_REST_Response $response): void
    {
        $response->header('X-Content-Type-Options', 'nosniff');
        $response->header('X-Frame-Options', 'DENY');
        $response->header('X-XSS-Protection', '1; mode=block');
    }
}

