<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Services\PortalService;
use CheapAlarms\Plugin\Services\Logger;
use CheapAlarms\Plugin\Services\EmailTemplateService;
use CheapAlarms\Plugin\Services\UserContextHelper;
use CheapAlarms\Plugin\Config\Config;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

use function check_password_reset_key;
use function email_exists;
use function get_password_reset_key;
use function get_user_by;
use function is_wp_error;
use function json_decode;
use function reset_password;
use function sanitize_email;
use function sanitize_text_field;
use function wp_create_user;
use function wp_generate_password;

class PasswordResetController implements ControllerInterface
{
    private Authenticator $authenticator;
    private GhlClient $ghlClient;
    private PortalService $portalService;
    private Config $config;
    private Logger $logger;

    public function __construct(private Container $container)
    {
        $this->authenticator = $this->container->get(Authenticator::class);
        $this->ghlClient = $this->container->get(GhlClient::class);
        $this->portalService = $this->container->get(PortalService::class);
        $this->config = $this->container->get(Config::class);
        $this->logger = $this->container->get(Logger::class);
    }

    public function register(): void
    {
        // Send password reset email via GHL
        register_rest_route('ca/v1', '/auth/send-password-reset', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => [$this, 'sendPasswordReset'],
        ]);

        // Validate reset key
        register_rest_route('ca/v1', '/auth/validate-reset-key', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => [$this, 'validateResetKey'],
        ]);

        // Reset password
        register_rest_route('ca/v1', '/auth/reset-password', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => [$this, 'resetPassword'],
        ]);

        // Check if account exists
        register_rest_route('ca/v1', '/auth/check-account', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => [$this, 'checkAccount'],
        ]);
    }

    /**
     * Send password reset email via GHL
     */
    public function sendPasswordReset(WP_REST_Request $request): WP_REST_Response
    {
        // SECURITY: Rate limit password reset requests to prevent brute force and account enumeration
        $rateCheck = $this->authenticator->enforceRateLimit('password_reset', 5, 300);
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }
        
        $payload = $this->getJsonPayload($request);

        $email = sanitize_email($payload['email'] ?? '');
        if (!$email) {
            return $this->respond(new WP_Error(
                'bad_request',
                __('Email is required.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Find or create WordPress user by email (auto-provisioning)
        $userId = email_exists($email);
        if (!$userId) {
            // Auto-provision: Create user with ca_customer role (has ca_access_portal capability)
            $password = wp_generate_password(20);
            $userId = wp_create_user($email, $password, $email);
            if (is_wp_error($userId)) {
                return $this->respond($userId);
            }
            
            // Set ca_customer role (has ca_access_portal capability)
            $user = get_user_by('id', $userId);
            if ($user) {
                $user->set_role('ca_customer');
            }
        } else {
            // Existing user - ensure they have ca_access_portal capability
            $user = get_user_by('id', $userId);
            if ($user && !$user->has_cap('ca_access_portal')) {
                // Add capability if missing
                $user->add_cap('ca_access_portal');
            }
        }

        $user = get_user_by('id', $userId);
        if (!$user) {
            return $this->respond(new WP_Error(
                'user_not_found',
                __('User account not found.', 'cheapalarms'),
                ['status' => 404]
            ));
        }

        // Generate password reset key
        $resetKey = get_password_reset_key($user);
        if (is_wp_error($resetKey)) {
            return $this->respond($resetKey);
        }

        // Get frontend URL (Next.js)
        $frontendUrl = $this->getFrontendUrl();
        
        // Extract estimateId and locationId from payload (if provided)
        $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
        $locationId = sanitize_text_field($payload['locationId'] ?? '');
        
        $resetUrl = $frontendUrl . '/set-password?key=' . rawurlencode($resetKey) . '&login=' . rawurlencode($user->user_login);
        if ($estimateId) {
            $resetUrl .= '&estimateId=' . rawurlencode($estimateId);
        }
        if ($locationId) {
            $resetUrl .= '&locationId=' . rawurlencode($locationId);
        }

        // Find or create GHL contact
        $locationId = $this->config->getLocationId();
        if (empty($locationId)) {
            return $this->respond(new WP_Error(
                'missing_location_id',
                __('GHL Location ID is not configured.', 'cheapalarms'),
                ['status' => 500]
            ));
        }

        $contactId = $this->findOrCreateGhlContact($email, $user, $locationId);
        if (is_wp_error($contactId)) {
            return $this->respond($contactId);
        }

        if (empty($contactId)) {
            return $this->respond(new WP_Error(
                'contact_not_found',
                __('Could not find or create GHL contact.', 'cheapalarms'),
                ['status' => 500]
            ));
        }

        // Ensure contact has email (required for messaging)
        $this->updateContactEmail($contactId, $email, $locationId);

        // Small delay to ensure GHL has fully processed the contact creation/update
        // This helps avoid race conditions where the contact exists but isn't ready for messaging
        usleep(1000000); // 1 second delay (increased from 0.5s)

        // Send email via GHL
        $emailResult = $this->sendPasswordResetEmailViaGhl($contactId, $email, $userId, $user->display_name ?: $user->user_login, $resetUrl, $locationId);
        if (is_wp_error($emailResult)) {
            return $this->respond($emailResult);
        }

        return new WP_REST_Response([
            'ok' => true,
            'message' => 'Password reset email sent successfully.',
        ], 200);
    }

    /**
     * Validate reset key
     */
    public function validateResetKey(WP_REST_Request $request): WP_REST_Response
    {
        // SECURITY: Rate limit reset key validation to prevent brute force
        $rateCheck = $this->authenticator->enforceRateLimit('validate_reset_key', 10, 300);
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }
        
        $payload = $this->getJsonPayload($request);

        $key = sanitize_text_field($payload['key'] ?? '');
        $login = sanitize_text_field($payload['login'] ?? '');

        if (!$key || !$login) {
            return $this->respond(new WP_Error(
                'bad_request',
                __('Reset key and login are required.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        $user = check_password_reset_key($key, $login);
        if (is_wp_error($user)) {
            return $this->respond($user);
        }

        if (!$user instanceof WP_User) {
            return $this->respond(new WP_Error(
                'invalid_key',
                __('Invalid or expired reset key.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        return new WP_REST_Response([
            'ok' => true,
            'user' => [
                'id' => $user->ID,
                'email' => $user->user_email,
                'login' => $user->user_login,
            ],
        ], 200);
    }

    /**
     * Check if account exists
     * SECURITY: Rate limited and returns generic response to prevent account enumeration
     */
    public function checkAccount(WP_REST_Request $request): WP_REST_Response
    {
        // SECURITY: Rate limit to prevent account enumeration attacks
        $rateCheck = $this->authenticator->enforceRateLimit('check_account', 10, 300);
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }
        
        $payload = $this->getJsonPayload($request);

        $email = sanitize_email($payload['email'] ?? '');
        if (!$email) {
            return $this->respond(new WP_Error(
                'bad_request',
                __('Email is required.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        $userId = email_exists($email);
        $user = $userId ? get_user_by('id', $userId) : null;

        // SECURITY: Return generic response regardless of account existence to prevent enumeration
        // Always return success with minimal information
        return new WP_REST_Response([
            'ok' => true,
            'message' => __('If an account exists, a password reset link will be sent.', 'cheapalarms'),
            // Do not reveal account existence status
        ], 200);
    }

    /**
     * Reset password
     */
    public function resetPassword(WP_REST_Request $request): WP_REST_Response
    {
        // SECURITY: Rate limit password reset attempts to prevent brute force
        $rateCheck = $this->authenticator->enforceRateLimit('reset_password', 5, 300);
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }
        
        $payload = $this->getJsonPayload($request);

        $key = sanitize_text_field($payload['key'] ?? '');
        $login = sanitize_text_field($payload['login'] ?? '');
        $newPassword = $payload['password'] ?? '';

        if (!$key || !$login || !$newPassword) {
            return $this->respond(new WP_Error(
                'bad_request',
                __('Reset key, login, and password are required.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Validate password strength
        if (strlen($newPassword) < 8) {
            return $this->respond(new WP_Error(
                'weak_password',
                __('Password must be at least 8 characters long.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Validate reset key
        $user = check_password_reset_key($key, $login);
        if (is_wp_error($user)) {
            return $this->respond($user);
        }

        if (!$user instanceof WP_User) {
            return $this->respond(new WP_Error(
                'invalid_key',
                __('Invalid or expired reset key.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Set new password
        reset_password($user, $newPassword);

        // Ensure user has ca_access_portal capability
        if (!$user->has_cap('ca_access_portal')) {
            // If user doesn't have the capability, add it or set ca_customer role
            if (!in_array('ca_customer', $user->roles, true)) {
                $user->set_role('ca_customer');
            } else {
                $user->add_cap('ca_access_portal');
            }
        }

        // Link user to estimate if estimateId is provided
        $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
        $locationId = sanitize_text_field($payload['locationId'] ?? '');
        if ($estimateId) {
            $linkResult = $this->portalService->linkEstimateToExistingAccount(
                $estimateId,
                $user->ID,
                $locationId ?: null
            );
            if (is_wp_error($linkResult)) {
                // Log error but don't fail the password reset
                $this->logger->warning('Failed to link estimate to user after password reset', [
                    'userId' => $user->ID,
                    'estimateId' => $estimateId,
                    'error' => $linkResult->get_error_message(),
                ]);
            }
        }

        // Issue token for auto-login
        $token = null;
        try {
            $token = $this->authenticator->issueToken($user);
            if (!$token || is_wp_error($token)) {
                // Log error but don't fail password reset
                error_log('[Password Reset] Failed to issue token: ' . (is_wp_error($token) ? $token->get_error_message() : 'Token is null'));
                // Return success without token - user can log in manually
                return new WP_REST_Response([
                    'ok' => true,
                    'message' => 'Password has been reset successfully. Please log in.',
                ], 200);
            }
        } catch (\Exception $e) {
            // Log exception but don't fail password reset
            error_log('[Password Reset] Exception issuing token: ' . $e->getMessage());
            // Return success without token - user can log in manually
            return new WP_REST_Response([
                'ok' => true,
                'message' => 'Password has been reset successfully. Please log in.',
            ], 200);
        }

        // Only return token if we successfully got one
        return new WP_REST_Response([
            'ok' => true,
            'message' => 'Password has been reset successfully.',
            'token' => $token['token'] ?? null,
            'expiresAt' => $token['expires_at'] ?? null,
            'expiresIn' => $token['expires_in'] ?? null,
            'user' => $token['user'] ?? null,
        ], 200);
    }

    /**
     * Get frontend URL (Next.js)
     */
    private function getFrontendUrl(): string
    {
        // Check for environment variable
        if (defined('CA_FRONTEND_URL') && CA_FRONTEND_URL) {
            return rtrim(CA_FRONTEND_URL, '/');
        }

        $envUrl = getenv('CA_FRONTEND_URL');
        if ($envUrl && $envUrl !== false) {
            return rtrim($envUrl, '/');
        }

        // Fallback: try to infer from WordPress URL
        $wpUrl = home_url();
        if (strpos($wpUrl, 'localhost') !== false || strpos($wpUrl, '127.0.0.1') !== false) {
            // Development: assume Next.js runs on port 3000
            return 'http://localhost:3000';
        }

        // Production: assume same domain, different port or subdomain
        // You may need to adjust this based on your setup
        return str_replace('/wp', '', $wpUrl);
    }

    /**
     * Find or create GHL contact by email
     * @return string|WP_Error GHL contact ID
     */
    private function findOrCreateGhlContact(string $email, WP_User $user, string $locationId): string|WP_Error
    {
        // Try to find existing contact
        $response = $this->ghlClient->get('/contacts/search', [
            'query' => $email,
        ], 20, $locationId);

        if (!is_wp_error($response)) {
            $contacts = $response['contacts'] ?? $response['items'] ?? [];
            foreach ($contacts as $contact) {
                $contactEmail = $contact['email'] ?? '';
                if ($contactEmail && strcasecmp($contactEmail, $email) === 0) {
                    $foundId = $contact['id'] ?? '';
                    if (!empty($foundId)) {
                        // Verify contact has email, update if missing
                        if (empty($contact['email'])) {
                            $this->updateContactEmail($foundId, $email, $locationId);
                        }
                        return $foundId;
                    }
                }
            }
        }

        // Create new contact if not found
        $firstName = $user->first_name ?: '';
        $lastName = $user->last_name ?: '';
        if (!$firstName && !$lastName) {
            $nameParts = explode(' ', $user->display_name ?: $user->user_login, 2);
            $firstName = $nameParts[0] ?? '';
            $lastName = $nameParts[1] ?? '';
        }

        // Ensure email is set for contact creation
        $contactData = [
            'email' => $email, // Always include email - required for messaging
            'locationId' => $locationId,
        ];
        
        if ($firstName) {
            $contactData['firstName'] = $firstName;
        }
        if ($lastName) {
            $contactData['lastName'] = $lastName;
        }

        $createResponse = $this->ghlClient->post('/contacts/', $contactData, 30, $locationId);

        if (is_wp_error($createResponse)) {
            // Check if this is a duplicate contact error
            $errorData = $createResponse->get_error_data();
            $errorCode = $createResponse->get_error_code();
            
            $this->logger->info('Contact creation returned error', [
                'errorCode' => $errorCode,
                'errorData' => $errorData,
                'email' => $email,
            ]);
            
            // GHL returns duplicate contact errors with contactId in metadata
            if ($errorCode === 'ghl_http_error' && isset($errorData['code']) && $errorData['code'] === 400) {
                $errorBody = $errorData['body'] ?? null;
                
                // Log raw body for debugging
                $this->logger->info('GHL 400 error body', [
                    'body' => $errorBody,
                    'bodyType' => gettype($errorBody),
                ]);
                
                if (is_string($errorBody)) {
                    $decoded = json_decode($errorBody, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $jsonError = 'JSON decode error: ' . json_last_error();
                        if (function_exists('json_last_error_msg')) {
                            $jsonError = json_last_error_msg();
                        }
                        $this->logger->warning('Failed to decode GHL error body', [
                            'jsonError' => $jsonError,
                            'body' => $errorBody,
                        ]);
                        $errorBody = null; // Don't use invalid JSON
                    } else {
                        $errorBody = $decoded;
                    }
                }
                
                // Check if error message indicates duplicate contact
                // GHL error structure: { "statusCode": 400, "message": "...", "meta": { "contactId": "..." } }
                if (is_array($errorBody)) {
                    $errorMessage = $errorBody['message'] ?? '';
                    $statusCode = $errorBody['statusCode'] ?? $errorData['code'] ?? null;
                    
                    $this->logger->info('Parsed GHL error', [
                        'statusCode' => $statusCode,
                        'message' => $errorMessage,
                        'meta' => $errorBody['meta'] ?? null,
                    ]);
                    
                    // Check for duplicate contact error - check if meta.contactId exists OR message contains duplicate
                    $hasContactId = isset($errorBody['meta']['contactId']) && !empty($errorBody['meta']['contactId']);
                    $hasDuplicateMessage = stripos($errorMessage, 'duplicate') !== false || stripos($errorMessage, 'duplicated') !== false;
                    
                    if ($statusCode === 400 && ($hasDuplicateMessage || $hasContactId)) {
                        // Extract contactId from error metadata
                        $meta = $errorBody['meta'] ?? [];
                        $existingContactId = $meta['contactId'] ?? '';
                        
                        if (!empty($existingContactId)) {
                            // Contact exists, use the existing contactId
                            $this->logger->info('Duplicate contact detected, using existing contactId', [
                                'email' => $email,
                                'contactId' => $existingContactId,
                                'errorMessage' => $errorMessage,
                            ]);
                            
                            // Ensure email is set on existing contact
                            $this->updateContactEmail($existingContactId, $email, $locationId);
                            
                            return $existingContactId;
                        } else {
                            $this->logger->warning('Duplicate contact error but no contactId in meta', [
                                'email' => $email,
                                'meta' => $meta,
                            ]);
                        }
                    }
                } else {
                    $this->logger->warning('GHL error body is not an array', [
                        'body' => $errorBody,
                        'bodyType' => gettype($errorBody),
                    ]);
                }
            }
            
            // For other errors, try searching again in case contact was just created
            // This handles race conditions
            $this->logger->info('Contact creation failed, retrying search', [
                'email' => $email,
                'error' => $createResponse->get_error_message(),
            ]);
            
            $retryResponse = $this->ghlClient->get('/contacts/search', [
                'query' => $email,
            ], 20, $locationId);
            
            if (!is_wp_error($retryResponse)) {
                $contacts = $retryResponse['contacts'] ?? $retryResponse['items'] ?? [];
                foreach ($contacts as $contact) {
                    $contactEmail = $contact['email'] ?? '';
                    if ($contactEmail && strcasecmp($contactEmail, $email) === 0) {
                        $foundId = $contact['id'] ?? '';
                        if (!empty($foundId)) {
                            $this->logger->info('Found contact on retry search', [
                                'email' => $email,
                                'contactId' => $foundId,
                            ]);
                            $this->updateContactEmail($foundId, $email, $locationId);
                            return $foundId;
                        }
                    }
                }
            }
            
            // If we still can't find it, return the original error
            return $createResponse;
        }

        // GHL API returns contact in different structures
        // Try multiple possible response structures in order of likelihood
        $contactId = '';
        
        // Structure 1: { contact: { id: "..." } }
        if (isset($createResponse['contact']) && is_array($createResponse['contact'])) {
            $contactId = $createResponse['contact']['id'] ?? '';
        }
        
        // Structure 2: { id: "..." } (direct ID)
        if (empty($contactId) && isset($createResponse['id'])) {
            $contactId = $createResponse['id'];
        }
        
        // Structure 3: { contactId: "..." }
        if (empty($contactId) && isset($createResponse['contactId'])) {
            $contactId = $createResponse['contactId'];
        }
        
        // Structure 4: Response itself might be the contact object
        if (empty($contactId) && isset($createResponse['id']) && is_string($createResponse['id'])) {
            $contactId = $createResponse['id'];
        }

        if (empty($contactId)) {
            return new WP_Error(
                'ghl_contact_creation_failed',
                __('Contact was created but no contact ID was returned.', 'cheapalarms'),
                ['status' => 500, 'response' => $createResponse]
            );
        }

        return $contactId;
    }

    /**
     * Update contact email in GHL if missing
     */
    private function updateContactEmail(string $contactId, string $email, string $locationId): void
    {
        // Try to update contact with email
        $updateResponse = $this->ghlClient->put('/contacts/' . $contactId, [
            'email' => $email,
        ], [], 30, $locationId);
        
        // Log but don't fail if update fails
        if (is_wp_error($updateResponse)) {
            // Silently fail - contact might still work
        }
    }

    /**
     * Send password reset email via GHL
     * Uses context-aware EmailTemplateService
     */
    private function sendPasswordResetEmailViaGhl(string $contactId, string $email, int $userId, string $name, string $resetUrl, string $locationId): bool|WP_Error
    {
        if (empty($contactId)) {
            return new WP_Error(
                'invalid_contact_id',
                __('Contact ID is required to send email.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Validate contactId is not just whitespace
        $contactId = trim($contactId);
        if (empty($contactId)) {
            return new WP_Error(
                'invalid_contact_id',
                __('Contact ID is required to send email.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        // Get user context for email personalization
        $userContext = UserContextHelper::getUserContext($userId, $email);
        
        // Render context-aware email template
        $emailTemplate = null;
        try {
            $emailTemplateService = $this->container->get(EmailTemplateService::class);
            $emailData = [
                'customerName' => $name,
                'resetUrl' => $resetUrl,
            ];
            
            $emailTemplate = $emailTemplateService->renderPasswordResetEmail($userContext, $emailData);
            $subject = $emailTemplate['subject'] ?? __('Set Your Password - CheapAlarms Portal', 'cheapalarms');
            $html = $emailTemplate['body'] ?? '';
            
            // Fallback if template rendering failed
            if (empty($html)) {
                error_log('[CheapAlarms][WARNING] Password reset email template returned empty body, using fallback');
                $subject = __('Set Your Password - CheapAlarms Portal', 'cheapalarms');
                $html = '<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">';
                $html .= '<div style="max-width: 600px; margin: 0 auto; padding: 20px;">';
                $html .= '<h2 style="color: #2563eb;">Set Your Password</h2>';
                $html .= '<p>Hi ' . esc_html($name) . ',</p>';
                $html .= '<p>Click the button below to set your password and access your CheapAlarms portal:</p>';
                $html .= '<p style="margin: 30px 0;">';
                $html .= '<a href="' . esc_url($resetUrl) . '" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Set Your Password</a>';
                $html .= '</p>';
                $html .= '<p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>';
                $html .= '<p style="color: #666; font-size: 12px; word-break: break-all;">' . esc_html($resetUrl) . '</p>';
                $html .= '<p style="color: #666; font-size: 14px; margin-top: 30px;">This link will expire in 24 hours.</p>';
                $html .= '<p style="margin-top: 30px;">Thanks,<br />CheapAlarms Team</p>';
                $html .= '</div></body></html>';
            }
        } catch (\Exception $e) {
            error_log('[CheapAlarms][ERROR] Failed to render password reset email template: ' . $e->getMessage());
            // Fallback to simple email
            $subject = __('Set Your Password - CheapAlarms Portal', 'cheapalarms');
            $html = '<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">';
            $html .= '<div style="max-width: 600px; margin: 0 auto; padding: 20px;">';
            $html .= '<h2 style="color: #2563eb;">Set Your Password</h2>';
            $html .= '<p>Hi ' . esc_html($name) . ',</p>';
            $html .= '<p>Click the button below to set your password and access your CheapAlarms portal:</p>';
            $html .= '<p style="margin: 30px 0;">';
            $html .= '<a href="' . esc_url($resetUrl) . '" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Set Your Password</a>';
            $html .= '</p>';
            $html .= '<p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>';
            $html .= '<p style="color: #666; font-size: 12px; word-break: break-all;">' . esc_html($resetUrl) . '</p>';
            $html .= '<p style="color: #666; font-size: 14px; margin-top: 30px;">This link will expire in 24 hours.</p>';
            $html .= '<p style="margin-top: 30px;">Thanks,<br />CheapAlarms Team</p>';
            $html .= '</div></body></html>';
        }

        $text = "Set Your Password\n\n";
        $text .= "Hi {$name},\n\n";
        $text .= "Click the link below to set your password and access your CheapAlarms portal:\n\n";
        $text .= $resetUrl . "\n\n";
        $text .= "This link will expire in 24 hours.\n\n";
        $text .= "Thanks,\nCheapAlarms Team";

        // Use exact same pattern as GhlController
        $effectiveFromEmail = get_option('ghl_from_email', 'quotes@cheapalarms.dev');

        $payload = [
            'contactId' => $contactId,
            'type' => 'Email',
            'status' => 'pending',
            'subject' => $subject,
            'html' => !empty($html) ? $html : null,
            'message' => !empty($text) ? $text : null,
            'emailFrom' => $effectiveFromEmail,
        ];

        // Always include locationId (required by GHL API)
        if (!empty($locationId)) {
            $payload['locationId'] = $locationId;
        } else {
            // Fallback to config locationId if not provided
            $configLocationId = $this->config->getLocationId();
            if (!empty($configLocationId)) {
                $payload['locationId'] = $configLocationId;
            }
        }

        $variation = isset($emailTemplate) ? ($emailTemplate['variation'] ?? 'A') : 'A';
        $this->logger->info('Sending password reset email via GHL', [
            'contactId' => $contactId,
            'email' => $email,
            'locationId' => $payload['locationId'] ?? 'not set',
            'variation' => $variation,
        ]);

        // Pass locationId as header if available
        $headerLocationId = $payload['locationId'] ?? $this->config->getLocationId();
        $result = $this->ghlClient->post('/conversations/messages', $payload, 30, $headerLocationId ?: null);
        
        if (is_wp_error($result)) {
            // Include more details in error message
            $errorData = $result->get_error_data();
            $errorMessage = $result->get_error_message();
            
            $this->logger->error('GHL password reset email failed', [
                'contactId' => $contactId,
                'email' => $email,
                'error' => $errorMessage,
                'errorData' => $errorData,
            ]);
            
            if (!empty($errorData['body'])) {
                $body = is_string($errorData['body']) ? json_decode($errorData['body'], true) : $errorData['body'];
                if (is_array($body)) {
                    if (isset($body['message'])) {
                        $errorMessage .= ': ' . $body['message'];
                    }
                    if (isset($body['errors']) && is_array($body['errors'])) {
                        $errorMessages = [];
                        foreach ($body['errors'] as $field => $messages) {
                            if (is_array($messages)) {
                                $errorMessages[] = $field . ': ' . implode(', ', $messages);
                            } else {
                                $errorMessages[] = $field . ': ' . $messages;
                            }
                        }
                        if (!empty($errorMessages)) {
                            $errorMessage .= ' - ' . implode('; ', $errorMessages);
                        }
                    }
                } elseif (is_string($errorData['body'])) {
                    $errorMessage .= ': ' . substr($errorData['body'], 0, 200);
                }
            }
            return new WP_Error(
                $result->get_error_code(),
                $errorMessage,
                $errorData
            );
        }

        return true;
    }

    /**
     * Get JSON payload from request
     *
     * @return array<string, mixed>
     */
    private function getJsonPayload(WP_REST_Request $request): array
    {
        $payload = $request->get_json_params();
        if (!is_array($payload)) {
            $payload = json_decode($request->get_body(), true);
        }
        if (!is_array($payload)) {
            $payload = [];
        }
        return $payload;
    }

    /**
     * Respond with WP_REST_Response
     */
    private function respond(WP_Error|array $result): WP_REST_Response
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
        $errorData = $error->get_error_data();
        
        // SECURITY: Sanitize error messages in production
        $isDebug = defined('WP_DEBUG') && WP_DEBUG;
        
        if (!$isDebug) {
            // Generic messages for production to prevent information disclosure
            $genericMessages = [
                'rest_forbidden' => 'Access denied.',
                'unauthorized' => 'Authentication required.',
                'invalid_token' => 'Invalid authentication token.',
                'rate_limited' => 'Too many requests. Please try again later.',
                'bad_request' => 'Invalid request.',
                'not_found' => 'Resource not found.',
                'server_error' => 'An error occurred. Please try again.',
                'invalid_reset_key' => 'Invalid or expired reset link.',
                'user_not_found' => 'User not found.',
                'ghl_api_error' => 'Service temporarily unavailable. Please try again.',
            ];
            
            $message = $genericMessages[$code] ?? 'An error occurred. Please try again.';
        }
        
        $response = [
            'ok'   => false,
            'error' => $message,
            'code' => $code,
            // Include 'err' for backward compatibility
            'err'  => $message,
        ];
        
        // Only include detailed error information in debug mode
        if ($isDebug && !empty($errorData) && is_array($errorData)) {
            $sanitized = $this->sanitizeErrorData($errorData);
            if (!empty($sanitized)) {
                $response['details'] = $sanitized;
            }
        }
        
        $restResponse = new WP_REST_Response($response, $status);
        $this->addSecurityHeaders($restResponse);
        return $restResponse;
    }

    /**
     * Remove sensitive data from error details
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function sanitizeErrorData(array $data): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'api_key'];
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            $keyLower = strtolower($key);
            $isSensitive = false;
            
            foreach ($sensitive as $sensitiveKey) {
                if (str_contains($keyLower, $sensitiveKey)) {
                    $isSensitive = true;
                    break;
                }
            }
            
            if ($isSensitive) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeErrorData($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * Add security headers to response
     *
     * @param WP_REST_Response $response
     * @return void
     */
    private function addSecurityHeaders(WP_REST_Response $response): void
    {
        // Prevent MIME type sniffing
        $response->header('X-Content-Type-Options', 'nosniff');
        
        // XSS protection (legacy but still useful)
        $response->header('X-XSS-Protection', '1; mode=block');
        
        // Prevent clickjacking
        $response->header('X-Frame-Options', 'DENY');
        
        // Referrer policy
        $response->header('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
}

