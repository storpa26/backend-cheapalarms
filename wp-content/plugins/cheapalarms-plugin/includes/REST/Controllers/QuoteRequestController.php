<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\PortalService;
use CheapAlarms\Plugin\Config\Config;
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
use function esc_url;
use function esc_html;
use function __;

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

    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->ghlClient = $container->get(GhlClient::class);
        $this->estimateService = $container->get(EstimateService::class);
        $this->portalService = $container->get(PortalService::class);
        $this->config = $container->get(Config::class);
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

            $contactResult = $this->ghlClient->post('/contacts/', $contactPayload);
            
            if (is_wp_error($contactResult)) {
                // Check for duplicate contact (GHL returns 400 with contactId in meta)
                $errorData = $contactResult->get_error_data();
                $errorCode = $contactResult->get_error_code();
                
                $contactId = null;
                if ($errorCode === 'ghl_http_error' && isset($errorData['code']) && $errorData['code'] === 400) {
                    $errorBody = $errorData['body'] ?? null;
                    if (is_string($errorBody)) {
                        $decoded = json_decode($errorBody, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $errorBody = $decoded;
                        }
                    }
                    
                    if (is_array($errorBody)) {
                        $contactId = $errorBody['meta']['contactId'] ?? null;
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

            // createEstimate only accepts one parameter (payload)
            $estimateResult = $this->estimateService->createEstimate($estimateData);
            
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
            
            if (!$estimateId) {
                return new WP_REST_Response([
                    'ok' => false,
                    'error' => 'Estimate created but ID missing in response',
                ], 500);
            }

            // Step 3: Create portal entry and send invitation
            // Generate invite token
            $inviteToken = bin2hex(random_bytes(16));
            
            // Use frontend URL (Next.js on Vercel) instead of WordPress backend URL
            $frontendUrl = $this->config->getFrontendUrl();
            $portalUrl = add_query_arg(
                [
                    'estimateId' => $estimateId,
                    'inviteToken' => $inviteToken,
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
            }

            // Build portal meta (will be saved after password reset generation)
            $portalMeta = [
                'account' => [
                    'inviteToken' => $inviteToken,
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
                    'status' => 'sent',
                    'statusLabel' => 'Sent',
                    'total' => null, // Will be populated when estimate is fetched
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

            // Save portal meta (no password reset - users access via invite token)
            update_option("ca_portal_meta_{$estimateId}", wp_json_encode($portalMeta));

            // Send invitation email via GHL Conversations API
            $displayName = trim("{$firstName} {$lastName}");
            $subject = __('Your CheapAlarms quote is ready', 'cheapalarms');
            
            $greeting = sprintf(__('Hi %s,', 'cheapalarms'), esc_html($displayName));
            $message = '<p>' . $greeting . '</p>';
            $message .= '<p>' . esc_html(__('We have prepared your quote. Click the button below to view your estimate and upload site photos:', 'cheapalarms')) . '</p>';
            $message .= '<p><a href="' . esc_url($portalUrl) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">' . esc_html(__('View My Quote', 'cheapalarms')) . '</a></p>';
            $message .= '<p>' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
            $message .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';
            
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
                error_log('[CheapAlarms][INFO] Quote invitation email sent via GHL to: ' . $email);
            } else {
                error_log('Failed to send GHL email to: ' . $email . ' - ' . ($emailResult instanceof WP_Error ? $emailResult->get_error_message() : 'Unknown error'));
            }

            // Success!
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
            error_log('Quote request error: ' . $e->getMessage());
            
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'An unexpected error occurred. Please try again.',
            ], 500);
        }
    }
}

