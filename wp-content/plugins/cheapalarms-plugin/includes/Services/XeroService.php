<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Services\Logger;
use WP_Error;
use function get_option;
use function update_option;
use function delete_option;
use function sanitize_text_field;
use function wp_generate_password;
use function set_transient;
use function get_transient;
use function delete_transient;
use function wp_salt;

/**
 * XeroService - Handles Xero API integration for invoice management
 * 
 * Note: Xero SDK (xero-node) is a Node.js package, so we'll use direct HTTP calls
 * to Xero's REST API from PHP instead.
 */
class XeroService
{
    private const XERO_API_BASE = 'https://api.xero.com/api.xro/2.0';
    private const XERO_AUTH_BASE = 'https://identity.xero.com'; // Used for token exchange
    private const XERO_AUTHORIZE_BASE = 'https://login.xero.com/identity'; // Use login.xero.com for authorization
    private const TOKEN_OPTION_KEY = 'ca_xero_tokens';
    private const TENANT_OPTION_KEY = 'ca_xero_tenant_id';
    private const REFRESH_LOCK_KEY = 'ca_xero_refresh_lock';
    private const REFRESH_LOCK_TTL = 30; // 30 seconds lock

    public function __construct(
        private Config $config,
        private Logger $logger
    ) {
    }

    /**
     * Get Xero OAuth authorization URL
     * 
     * @return array|WP_Error Returns array with 'ok', 'authUrl', and 'state' keys, or WP_Error on failure
     */
    public function getAuthorizationUrl()
    {
        $clientId = $this->config->getXeroClientId();
        $redirectUri = $this->config->getXeroRedirectUri();

        if (empty($clientId) || empty($redirectUri)) {
            return new WP_Error('xero_not_configured', __('Xero credentials not configured.', 'cheapalarms'), ['status' => 500]);
        }

        // Scopes needed for invoice management
        // Note: offline_access and openid are required OAuth scopes
        // accounting.contacts provides both read and write access (accounting.contacts.write is not a valid scope)
        $scopes = [
            'offline_access', // Required: allows refresh tokens
            'openid', // Required: OAuth 2.0 OpenID Connect scope
            'accounting.transactions',
            'accounting.contacts', // Read + write access to contacts
            'accounting.settings.read',
        ];

        $scopeString = implode(' ', $scopes);
        $state = wp_generate_password(32, false); // CSRF protection

        // Store state temporarily
        set_transient('ca_xero_oauth_state', $state, 600); // 10 minutes

        $params = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $scopeString,
            'state' => $state,
            'prompt' => 'consent', // Force authorization screen even if already authorized
        ];

        // Use login.xero.com/identity/connect/authorize for authorization
        // This maintains the OAuth consent transaction through the login handoff
        $authUrl = self::XERO_AUTHORIZE_BASE . '/connect/authorize?' . http_build_query($params);

        return [
            'ok' => true,
            'authUrl' => $authUrl,
            'state' => $state,
        ];
    }

    /**
     * Exchange authorization code for access token
     * 
     * @param string $code Authorization code from Xero
     * @param string $state CSRF state token
     * @return array|WP_Error
     */
    public function exchangeCodeForToken(string $code, string $state)
    {
        // Verify state
        $storedState = get_transient('ca_xero_oauth_state');
        if ($storedState !== $state) {
            return new WP_Error('invalid_state', __('Invalid state parameter. Possible CSRF attack.', 'cheapalarms'), ['status' => 400]);
        }
        delete_transient('ca_xero_oauth_state');

        $clientId = $this->config->getXeroClientId();
        $clientSecret = $this->config->getXeroClientSecret();
        $redirectUri = $this->config->getXeroRedirectUri();

        $tokenUrl = self::XERO_AUTH_BASE . '/connect/token';

        $response = wp_remote_post($tokenUrl, [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => 'Basic ' . base64_encode($clientId . ':' . $clientSecret),
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
            ],
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('Xero token exchange failed', ['error' => $response->get_error_message()]);
            return $response;
        }

        $statusCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($statusCode !== 200) {
            $this->logger->error('Xero token exchange failed', [
                'status' => $statusCode,
                'body' => $body,
            ]);
            return new WP_Error('xero_token_error', __('Failed to exchange authorization code for token.', 'cheapalarms'), ['status' => $statusCode]);
        }

        $data = json_decode($body, true);
        if (!$data || !isset($data['access_token'])) {
            return new WP_Error('xero_token_parse_error', __('Invalid response from Xero token endpoint.', 'cheapalarms'), ['status' => 500]);
        }

        // Store tokens securely
        // Xero always provides a refresh_token in the initial token exchange
        if (!isset($data['refresh_token']) || empty($data['refresh_token'])) {
            $this->logger->error('Xero refresh token missing in initial token exchange', ['data_keys' => array_keys($data)]);
            return new WP_Error('xero_refresh_token_missing', __('No refresh token provided in initial token exchange. Please try again.', 'cheapalarms'), ['status' => 500]);
        }
        
        $accessToken = $data['access_token'];
        
        // Xero doesn't return tenant_id in token response - we must fetch it from /connections endpoint
        // The field is tenantId (camelCase), not tenant_id
        $connectionsUrl = 'https://api.xero.com/connections';
        $connectionsResponse = wp_remote_get($connectionsUrl, [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken,
                'Accept' => 'application/json',
            ],
        ]);
        
        $tenantId = null;
        if (is_wp_error($connectionsResponse)) {
            $this->logger->error('Failed to fetch Xero connections', ['error' => $connectionsResponse->get_error_message()]);
            return new WP_Error('xero_connections_error', __('Failed to retrieve organization information from Xero.', 'cheapalarms'), ['status' => 500]);
        }
        
        $connectionsStatusCode = wp_remote_retrieve_response_code($connectionsResponse);
        $connectionsBody = wp_remote_retrieve_body($connectionsResponse);
        
        if ($connectionsStatusCode !== 200) {
            $this->logger->error('Xero connections endpoint returned error', [
                'status' => $connectionsStatusCode,
                'body' => $connectionsBody,
            ]);
            return new WP_Error('xero_connections_error', __('Failed to retrieve organization information from Xero.', 'cheapalarms'), ['status' => $connectionsStatusCode]);
        }
        
        $connectionsData = json_decode($connectionsBody, true);
        if (!is_array($connectionsData) || empty($connectionsData)) {
            $this->logger->error('No Xero connections found', ['response' => $connectionsBody]);
            return new WP_Error('xero_no_connections', __('No organization was connected. Please ensure you selected an organization during authorization.', 'cheapalarms'), ['status' => 500]);
        }
        
        // Get the first connected organization's tenant ID
        // Field is tenantId (camelCase), not tenant_id
        $firstConnection = $connectionsData[0] ?? null;
        if (!$firstConnection || !isset($firstConnection['tenantId'])) {
            $this->logger->error('Invalid connection data structure', [
                'connection' => $firstConnection,
                'all_connections' => $connectionsData,
            ]);
            return new WP_Error('xero_invalid_connection', __('Invalid organization connection data from Xero.', 'cheapalarms'), ['status' => 500]);
        }
        
        $tenantId = $firstConnection['tenantId'];
        
        $this->logger->info('Retrieved tenant ID from Xero connections', [
            'tenantId' => $tenantId,
            'tenantName' => $firstConnection['tenantName'] ?? 'Unknown',
            'totalConnections' => count($connectionsData),
        ]);
        
        $tokens = [
            'access_token' => $accessToken,
            'refresh_token' => $data['refresh_token'],
            'expires_at' => time() + ($data['expires_in'] ?? 1800), // Default 30 minutes
            'tenant_id' => $tenantId,
        ];

        $this->storeTokens($tokens);
        if (!empty($tokens['tenant_id'])) {
            update_option(self::TENANT_OPTION_KEY, $tokens['tenant_id']);
        }

        $this->logger->info('Xero tokens stored successfully', ['tenantId' => $tenantId]);

        return [
            'ok' => true,
            'tenantId' => $tokens['tenant_id'],
        ];
    }

    /**
     * Refresh access token using refresh token
     * 
     * @return array|WP_Error
     */
    private function refreshAccessToken()
    {
        // Acquire lock to prevent concurrent refresh attempts
        $lockKey = self::REFRESH_LOCK_KEY;
        $lockValue = wp_generate_password(16, false);
        
        // Try to acquire lock (set if not exists)
        $existingLock = get_transient($lockKey);
        if ($existingLock !== false) {
            // Another process is refreshing, wait a bit and check if it completed
            sleep(1);
            $tokens = $this->getTokens();
            if ($tokens && !empty($tokens['access_token'])) {
                // Check if token was refreshed (expires_at updated)
                $expiresAt = $tokens['expires_at'] ?? 0;
                if ($expiresAt > time() + 300) {
                    // Token was refreshed, return it
                    return $tokens;
                }
            }
            // Still locked, return error
            return new WP_Error('refresh_in_progress', __('Token refresh is already in progress. Please try again shortly.', 'cheapalarms'), ['status' => 429]);
        }
        
        // Acquire lock
        set_transient($lockKey, $lockValue, self::REFRESH_LOCK_TTL);
        
        try {
            $tokens = $this->getTokens();
            if (!$tokens || empty($tokens['refresh_token'])) {
                delete_transient($lockKey);
                return new WP_Error('no_refresh_token', __('No refresh token available. Please reconnect Xero.', 'cheapalarms'), ['status' => 401]);
            }

            $clientId = $this->config->getXeroClientId();
            $clientSecret = $this->config->getXeroClientSecret();

            $tokenUrl = self::XERO_AUTH_BASE . '/connect/token';

            $response = wp_remote_post($tokenUrl, [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Authorization' => 'Basic ' . base64_encode($clientId . ':' . $clientSecret),
                ],
                'body' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $tokens['refresh_token'],
                ],
            ]);

            if (is_wp_error($response)) {
                delete_transient($lockKey);
                return $response;
            }

            $statusCode = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            if ($statusCode !== 200) {
                $this->logger->error('Xero token refresh failed', [
                    'status' => $statusCode,
                    'body' => $body,
                ]);
                delete_transient($lockKey);
                return new WP_Error('xero_refresh_error', __('Failed to refresh Xero token.', 'cheapalarms'), ['status' => $statusCode]);
            }

            $data = json_decode($body, true);
            if (!$data || !isset($data['access_token'])) {
                delete_transient($lockKey);
                return new WP_Error('xero_refresh_parse_error', __('Invalid response from Xero refresh endpoint.', 'cheapalarms'), ['status' => 500]);
            }

            // Update tokens
            // Xero uses rotating refresh tokens - a new one is ALWAYS provided
            if (!isset($data['refresh_token']) || empty($data['refresh_token'])) {
                $this->logger->error('Xero refresh token missing in response', ['data_keys' => array_keys($data)]);
                delete_transient($lockKey);
                return new WP_Error('xero_refresh_token_missing', __('No refresh token provided in response. Please reconnect Xero.', 'cheapalarms'), ['status' => 500]);
            }
            
            $tokens['access_token'] = $data['access_token'];
            $tokens['refresh_token'] = $data['refresh_token']; // Always use new rotating token
            $tokens['expires_at'] = time() + ($data['expires_in'] ?? 1800);

            $this->storeTokens($tokens);
            
            // Update tenant ID in separate storage if it exists (for consistency)
            if (!empty($tokens['tenant_id'])) {
                update_option(self::TENANT_OPTION_KEY, $tokens['tenant_id']);
            }
            
            // Release lock
            delete_transient($lockKey);
            
            return $tokens;
        } catch (\Exception $e) {
            // Release lock on error
            delete_transient($lockKey);
            $this->logger->error('Xero token refresh exception', ['error' => $e->getMessage()]);
            return new WP_Error('xero_refresh_exception', __('An error occurred while refreshing the token.', 'cheapalarms'), ['status' => 500]);
        }
    }

    /**
     * Get valid access token (refresh if needed)
     * 
     * @return string|WP_Error
     */
    private function getAccessToken()
    {
        $tokens = $this->getTokens();
        if (!$tokens || empty($tokens['access_token'])) {
            return new WP_Error('no_token', __('Xero not connected. Please authorize the app.', 'cheapalarms'), ['status' => 401]);
        }

        // Check if token is expired (refresh 5 minutes before expiry)
        if (time() >= ($tokens['expires_at'] ?? 0) - 300) {
            $refreshed = $this->refreshAccessToken();
            if (is_wp_error($refreshed)) {
                return $refreshed;
            }
            $tokens = $refreshed;
        }

        return $tokens['access_token'];
    }

    /**
     * Get tenant ID
     * 
     * @return string|WP_Error
     */
    private function getTenantId()
    {
        $tenantId = get_option(self::TENANT_OPTION_KEY);
        if (empty($tenantId)) {
            return new WP_Error('no_tenant_id', __('Xero tenant ID not found. Please reconnect Xero.', 'cheapalarms'), ['status' => 401]);
        }
        return $tenantId;
    }

    /**
     * Make authenticated request to Xero API
     * 
     * @param string $method HTTP method
     * @param string $endpoint API endpoint (without base URL)
     * @param array $data Request body data
     * @return array|WP_Error
     */
    private function makeRequest(string $method, string $endpoint, array $data = [])
    {
        $accessToken = $this->getAccessToken();
        if (is_wp_error($accessToken)) {
            return $accessToken;
        }

        $tenantId = $this->getTenantId();
        if (is_wp_error($tenantId)) {
            return $tenantId;
        }

        $url = self::XERO_API_BASE . $endpoint;

        $args = [
            'method' => $method,
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken,
                'Xero-tenant-id' => $tenantId,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ];

        if (!empty($data) && in_array($method, ['POST', 'PUT', 'PATCH'])) {
            $args['body'] = json_encode($data);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            $this->logger->error('Xero API request failed', [
                'endpoint' => $endpoint,
                'error' => $response->get_error_message(),
            ]);
            return $response;
        }

        $statusCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        // Monitor rate limit headers proactively
        $rateLimitRemaining = wp_remote_retrieve_header($response, 'x-rate-limit-remaining');
        $rateLimitLimit = wp_remote_retrieve_header($response, 'x-rate-limit-limit');
        if ($rateLimitRemaining !== null) {
            $remaining = (int)$rateLimitRemaining;
            $limit = $rateLimitLimit ? (int)$rateLimitLimit : 60;
            
            // Log warning if approaching limit (less than 10% remaining)
            if ($remaining < ($limit * 0.1)) {
                $this->logger->warning('Xero API rate limit approaching', [
                    'remaining' => $remaining,
                    'limit' => $limit,
                    'endpoint' => $endpoint,
                    'percentage_remaining' => round(($remaining / $limit) * 100, 1) . '%',
                ]);
            }
        }

        // Handle 401 - token might be expired, try refresh once
        if ($statusCode === 401) {
            $this->logger->warning('Xero API returned 401, attempting token refresh');
            $refreshed = $this->refreshAccessToken();
            if (!is_wp_error($refreshed)) {
                // Retry request with new token
                $args['headers']['Authorization'] = 'Bearer ' . $refreshed['access_token'];
                $response = wp_remote_request($url, $args);
                if (is_wp_error($response)) {
                    return $response;
                }
                $statusCode = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                
                // Check rate limit on retry as well
                $rateLimitRemaining = wp_remote_retrieve_header($response, 'x-rate-limit-remaining');
                if ($rateLimitRemaining !== null) {
                    $remaining = (int)$rateLimitRemaining;
                    $limit = wp_remote_retrieve_header($response, 'x-rate-limit-limit') ? (int)wp_remote_retrieve_header($response, 'x-rate-limit-limit') : 60;
                    if ($remaining < ($limit * 0.1)) {
                        $this->logger->warning('Xero API rate limit approaching (after retry)', [
                            'remaining' => $remaining,
                            'limit' => $limit,
                            'endpoint' => $endpoint,
                        ]);
                    }
                }
            }
        }

        $data = json_decode($body, true);

        if ($statusCode >= 400) {
            // Handle rate limiting (429 Too Many Requests)
            if ($statusCode === 429) {
                $retryAfter = wp_remote_retrieve_header($response, 'Retry-After') ?: 60;
                $this->logger->warning('Xero API rate limit exceeded', [
                    'endpoint' => $endpoint,
                    'retry_after' => $retryAfter,
                ]);
                return new WP_Error(
                    'xero_rate_limit',
                    sprintf(__('Xero API rate limit exceeded. Please retry after %d seconds.', 'cheapalarms'), $retryAfter),
                    ['status' => 429, 'retry_after' => $retryAfter]
                );
            }
            
            // Extract error message from Xero response
            $errorMessage = 'Xero API error';
            $validationErrors = [];
            
            if (is_array($data)) {
                // Xero error responses can have different structures
                $errorMessage = $data['Message'] ?? 
                               $data['message'] ?? 
                               $data['ErrorDescription'] ?? 
                               $data['error_description'] ?? 
                               null;
                
                // Extract ALL validation errors from all elements
                if (!empty($data['Elements']) && is_array($data['Elements'])) {
                    foreach ($data['Elements'] as $element) {
                        if (!empty($element['ValidationErrors']) && is_array($element['ValidationErrors'])) {
                            foreach ($element['ValidationErrors'] as $validationError) {
                                $validationMessage = $validationError['Message'] ?? 'Unknown validation error';
                                $validationErrors[] = $validationMessage;
                            }
                        }
                    }
                }
                
                // If we found validation errors, use them for a more detailed error message
                if (!empty($validationErrors)) {
                    $errorMessage = 'Validation errors: ' . implode('; ', $validationErrors);
                } elseif (!$errorMessage) {
                    // Fallback if no message found
                    $errorMessage = 'Xero API error';
                }
            }
            
            $this->logger->error('Xero API error', [
                'endpoint' => $endpoint,
                'status' => $statusCode,
                'error' => $errorMessage,
                'validation_errors' => $validationErrors,
                'full_response' => $data, // Log full response for debugging
                'body' => $body,
            ]);
            
            return new WP_Error('xero_api_error', $errorMessage, [
                'status' => $statusCode, 
                'data' => $data,
                'validation_errors' => $validationErrors,
            ]);
        }

        return $data;
    }

    /**
     * Create or update contact in Xero
     * Handles duplicate name errors by searching by name and making names unique when needed
     * 
     * @param array $contactData Contact information
     * @return array|WP_Error
     */
    public function upsertContact(array $contactData)
    {
        // Validate email
        $email = trim($contactData['email'] ?? '');
        if (empty($email)) {
            return new WP_Error('missing_email', __('Contact email is required.', 'cheapalarms'), ['status' => 400]);
        }
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return new WP_Error('invalid_email', __('Invalid email address format.', 'cheapalarms'), ['status' => 400]);
        }

        $contactName = trim($contactData['name'] ?? '');
        if (empty($contactName)) {
            $contactName = 'Unknown';
        }

        // Step 1: Try to find by email (don't fail if search fails - continue to create)
        $existingContact = null;
        $escapedEmail = str_replace('"', '""', $email); // OData escape: double quotes
        $whereClause = 'EmailAddress="' . $escapedEmail . '"';
        $searchResult = $this->makeRequest('GET', '/Contacts?where=' . urlencode($whereClause));
        
        // Don't abort on search failure - continue to create (will handle duplicate error if contact exists)
        if (!is_wp_error($searchResult) && !empty($searchResult['Contacts']) && count($searchResult['Contacts']) > 0) {
            $existingContact = $searchResult['Contacts'][0];
        }

        // Step 2: Prepare contact data
        $xeroContact = $this->prepareContactData($contactData, $contactName, $email);
        
        // Step 3: Execute operation
        if ($existingContact) {
            // Update existing contact
            $existingName = $existingContact['Name'] ?? '';
            
            // Prevent name conflict on update - check if new name would conflict
            if ($existingName !== $contactName) {
                $nameConflict = $this->findContactByName($contactName);
                if ($nameConflict && ($nameConflict['ContactID'] ?? '') !== ($existingContact['ContactID'] ?? '')) {
                    // Name conflict - keep existing name to avoid duplicate error
                    $xeroContact['Name'] = $existingName;
                    $this->logger->info('Name conflict detected on update, preserving existing contact name', [
                        'contactId' => $existingContact['ContactID'],
                        'existingName' => $existingName,
                        'requestedName' => $contactName,
                    ]);
                }
            }
            
            $xeroContact['ContactID'] = $existingContact['ContactID'];
            $result = $this->makeRequest('POST', '/Contacts', ['Contacts' => [$xeroContact]]);
            
            // Handle duplicate name error on update (rare but possible)
            if (is_wp_error($result) && $this->isDuplicateNameError($result)) {
                $this->logger->warning('Duplicate name error on update, retrying with existing name', [
                    'contactId' => $existingContact['ContactID'],
                    'existingName' => $existingName,
                ]);
                // Keep existing name and retry
                $xeroContact['Name'] = $existingName;
                $result = $this->makeRequest('POST', '/Contacts', ['Contacts' => [$xeroContact]]);
            }
        } else {
            // Try to create new contact
            $result = $this->makeRequest('PUT', '/Contacts', ['Contacts' => [$xeroContact]]);
            
            // Step 4: Handle duplicate name error on create
            if (is_wp_error($result) && $this->isDuplicateNameError($result)) {
                $this->logger->info('Duplicate name error detected, searching by name', [
                    'name' => $contactName,
                    'email' => $email,
                ]);
                
                // Search by name to find existing contact
                $existingByName = $this->findContactByName($contactName);
                
                if ($existingByName) {
                    // Found contact with same name - check if it's the same person
                    $existingEmail = strtolower(trim($existingByName['EmailAddress'] ?? ''));
                    $requestedEmail = strtolower(trim($email));
                    
                    if ($existingEmail === $requestedEmail || empty($existingEmail)) {
                        // Same person or email missing - update existing contact
                        $this->logger->info('Found existing contact by name with matching/empty email, updating', [
                            'contactId' => $existingByName['ContactID'],
                            'name' => $contactName,
                            'email' => $email,
                        ]);
                        
                        $xeroContact['ContactID'] = $existingByName['ContactID'];
                        $xeroContact['EmailAddress'] = $email; // Ensure email is set
                        $result = $this->makeRequest('POST', '/Contacts', ['Contacts' => [$xeroContact]]);
                    } else {
                        // Different person with same name - make name unique
                        $this->logger->info('Different person with same name, making name unique', [
                            'existingEmail' => $existingEmail,
                            'newEmail' => $requestedEmail,
                            'name' => $contactName,
                        ]);
                        
                        $uniqueName = $this->makeNameUnique($contactName, $email);
                        $xeroContact['Name'] = $uniqueName;
                        $result = $this->makeRequest('PUT', '/Contacts', ['Contacts' => [$xeroContact]]);
                        
                        // If still fails, try numbered suffix
                        if (is_wp_error($result) && $this->isDuplicateNameError($result)) {
                            $result = $this->retryWithNumberedSuffix($xeroContact, $contactName, $email);
                        }
                    }
                } else {
                    // Name conflict but contact not found - make name unique
                    $this->logger->warning('Duplicate name error but contact not found, making name unique', [
                        'name' => $contactName,
                        'email' => $email,
                    ]);
                    
                    $uniqueName = $this->makeNameUnique($contactName, $email);
                    $xeroContact['Name'] = $uniqueName;
                    $result = $this->makeRequest('PUT', '/Contacts', ['Contacts' => [$xeroContact]]);
                    
                    // If still fails, try numbered suffix
                    if (is_wp_error($result) && $this->isDuplicateNameError($result)) {
                        $result = $this->retryWithNumberedSuffix($xeroContact, $contactName, $email);
                    }
                }
            }
        }

        // Step 5: Final verification
        if (is_wp_error($result)) {
            return $result;
        }

        $contact = $result['Contacts'][0] ?? null;
        if (!$contact) {
            return new WP_Error('contact_creation_failed', __('Failed to create/update contact in Xero.', 'cheapalarms'), ['status' => 500]);
        }

        return [
            'ok' => true,
            'contact' => $contact,
            'contactId' => $contact['ContactID'],
        ];
    }

    /**
     * Find contact by exact name match
     * 
     * @param string $name Contact name to search for
     * @return array|null Contact data or null if not found
     */
    private function findContactByName(string $name): ?array
    {
        try {
            $escapedName = str_replace('"', '""', $name); // OData escape: double quotes
            $whereClause = 'Name="' . $escapedName . '"';
            $searchResult = $this->makeRequest('GET', '/Contacts?where=' . urlencode($whereClause));
            
            if (!is_wp_error($searchResult) && !empty($searchResult['Contacts'])) {
                return $searchResult['Contacts'][0];
            }
        } catch (\Exception $e) {
            $this->logger->warning('Name search failed', [
                'name' => $name,
                'error' => $e->getMessage(),
            ]);
        }
        return null;
    }

    /**
     * Make contact name unique by appending email-based suffix
     * 
     * @param string $baseName Original contact name
     * @param string $email Contact email (used for suffix)
     * @return string Unique name within Xero limits (150 chars)
     */
    private function makeNameUnique(string $baseName, string $email): string
    {
        // Use last 4 chars of email username as suffix (more readable than MD5)
        $emailParts = explode('@', $email);
        $emailUsername = $emailParts[0] ?? '';
        $suffix = !empty($emailUsername) && strlen($emailUsername) >= 4 
            ? substr($emailUsername, -4) 
            : substr(md5($email), 0, 4);
        
        // Ensure name fits within Xero limits (150 chars conservative)
        $maxLength = 150;
        $suffixWithParens = " ({$suffix})";
        $suffixLength = strlen($suffixWithParens);
        $maxBaseLength = $maxLength - $suffixLength;
        
        if (strlen($baseName) > $maxBaseLength) {
            $baseName = substr($baseName, 0, $maxBaseLength - 3) . '...';
        }
        
        return $baseName . $suffixWithParens;
    }

    /**
     * Retry contact creation with numbered suffix (1), (2), etc.
     * 
     * @param array $xeroContact Contact data array
     * @param string $baseName Original contact name
     * @param string $email Contact email
     * @return array|WP_Error Result from Xero API
     */
    private function retryWithNumberedSuffix(array $xeroContact, string $baseName, string $email): WP_Error|array
    {
        $maxAttempts = 10;
        
        for ($counter = 1; $counter <= $maxAttempts; $counter++) {
            $uniqueName = $baseName . ' (' . $counter . ')';
            
            // Ensure name fits within 150 char limit
            if (strlen($uniqueName) > 150) {
                $maxBaseLength = 150 - strlen(' (' . $counter . ')');
                $uniqueName = substr($baseName, 0, $maxBaseLength - 3) . '... (' . $counter . ')';
            }
            
            $xeroContact['Name'] = $uniqueName;
            $result = $this->makeRequest('PUT', '/Contacts', ['Contacts' => [$xeroContact]]);
            
            // If success, return immediately
            if (!is_wp_error($result)) {
                $this->logger->info('Successfully created contact with numbered suffix', [
                    'attempt' => $counter,
                    'uniqueName' => $uniqueName,
                ]);
                return $result;
            }
            
            // If error but not duplicate name error, return the error
            if (!$this->isDuplicateNameError($result)) {
                return $result;
            }
            
            // If duplicate name error, continue loop to try next number
        }
        
        $this->logger->error('Failed to create contact after all retry attempts', [
            'baseName' => $baseName,
            'email' => $email,
            'attempts' => $maxAttempts,
        ]);
        
        return new WP_Error(
            'contact_creation_failed',
            __('Failed to create contact after multiple attempts. Please try again.', 'cheapalarms'),
            ['status' => 500]
        );
    }

    /**
     * Check if error is a duplicate name error from Xero
     * 
     * @param WP_Error $error Error object to check
     * @return bool True if duplicate name error
     */
    private function isDuplicateNameError(WP_Error $error): bool
    {
        $errorMessage = strtolower($error->get_error_message());
        $errorData = $error->get_error_data();
        
        // Safely extract validation errors (errorData can be null or non-array)
        $validationErrors = [];
        if (is_array($errorData) && isset($errorData['validation_errors']) && is_array($errorData['validation_errors'])) {
            $validationErrors = $errorData['validation_errors'];
        }
        
        // Check validation errors for duplicate name
        foreach ($validationErrors as $validationError) {
            if (!is_string($validationError)) {
                continue;
            }
            $lowerError = strtolower($validationError);
            if ((stripos($lowerError, 'duplicate') !== false && stripos($lowerError, 'name') !== false) ||
                stripos($lowerError, 'already exists') !== false) {
                return true;
            }
        }
        
        // Check main error message
        if (stripos($errorMessage, 'duplicate') !== false || 
            stripos($errorMessage, 'already exists') !== false) {
            return true;
        }
        
        return false;
    }

    /**
     * Prepare contact data for Xero API
     * 
     * @param array $contactData Contact information from GHL
     * @param string $contactName Contact name
     * @param string $email Contact email
     * @return array Xero contact data array
     */
    private function prepareContactData(array $contactData, string $contactName, string $email): array
    {
        $xeroContact = [
            'Name' => $contactName,
            'EmailAddress' => $email,
            'ContactStatus' => 'ACTIVE',
        ];
        
        // Only include FirstName/LastName if provided (omit empty strings)
        $firstName = trim($contactData['firstName'] ?? '');
        $lastName = trim($contactData['lastName'] ?? '');
        if (!empty($firstName)) {
            $xeroContact['FirstName'] = $firstName;
        }
        if (!empty($lastName)) {
            $xeroContact['LastName'] = $lastName;
        }

        // Add address if provided (only include non-empty fields)
        if (!empty($contactData['address'])) {
            $address = [];
            $addressLine1 = trim($contactData['address']['addressLine1'] ?? '');
            $city = trim($contactData['address']['city'] ?? '');
            $region = trim($contactData['address']['state'] ?? '');
            $postalCode = trim($contactData['address']['postalCode'] ?? '');
            $country = trim($contactData['address']['countryCode'] ?? 'AU');
            
            // Only add address if at least one field is provided
            if (!empty($addressLine1) || !empty($city) || !empty($region) || !empty($postalCode)) {
                $address['AddressType'] = 'STREET';
                if (!empty($addressLine1)) {
                    $address['AddressLine1'] = $addressLine1;
                }
                if (!empty($city)) {
                    $address['City'] = $city;
                }
                if (!empty($region)) {
                    $address['Region'] = $region;
                }
                if (!empty($postalCode)) {
                    $address['PostalCode'] = $postalCode;
                }
                if (!empty($country)) {
                    $address['Country'] = $country;
                }
                $xeroContact['Addresses'] = [$address];
            }
        }

        // Add phone if provided (with basic validation)
        if (!empty($contactData['phone'])) {
            $phone = trim($contactData['phone']);
            // Basic phone validation: remove common formatting, check if it has at least 7 digits
            $phoneDigits = preg_replace('/[^0-9]/', '', $phone);
            if (strlen($phoneDigits) >= 7) {
                $xeroContact['Phones'] = [[
                    'PhoneType' => 'MOBILE',
                    'PhoneNumber' => $phone,
                ]];
            } else {
                $this->logger->warning('Invalid phone number format, omitting from contact', [
                    'phone' => $phone,
                    'digits' => $phoneDigits,
                ]);
            }
        }
        
        return $xeroContact;
    }

    /**
     * Create invoice in Xero from GHL invoice data
     * 
     * @param array $ghlInvoice GHL invoice data
     * @param array $contactData Contact information
     * @return array|WP_Error
     */
    public function createInvoice(array $ghlInvoice, array $contactData)
    {
        // First, ensure contact exists in Xero
        $contactResult = $this->upsertContact($contactData);
        if (is_wp_error($contactResult)) {
            return $contactResult;
        }
        $xeroContactId = $contactResult['contactId'];

        // Map GHL invoice items to Xero line items
        $lineItems = [];
        $items = $ghlInvoice['items'] ?? [];
        
        // Calculate totals
        $subTotal = $ghlInvoice['subtotal'] ?? 0;
        $taxTotal = $ghlInvoice['tax'] ?? 0;
        $total = $ghlInvoice['total'] ?? ($subTotal + $taxTotal);
        
        // Determine if tax is included or excluded in line item amounts
        // Logic:
        // - If taxTotal > 0 AND (subTotal + taxTotal) ≈ total: tax is EXCLUDED (added on top)
        // - If taxTotal > 0 AND subTotal ≈ total: tax is INCLUDED (already in amounts)
        // - If taxTotal = 0: no tax
        $isTaxIncluded = false;
        if ($taxTotal > 0) {
            // Check if subtotal equals total (meaning tax is already included in line item amounts)
            $isTaxIncluded = (abs($subTotal - $total) < 0.01);
            // If subtotal + tax = total, then tax is excluded (will be added by Xero)
        }
        
        // Get account codes from config
        // Can be configured via environment variable CA_XERO_SALES_ACCOUNT_CODE
        // or in secrets.php as 'xero_sales_account_code'
        $salesAccountCode = $this->config->getXeroSalesAccountCode();
        
        // Validate sales account code
        if (empty($salesAccountCode)) {
            return new WP_Error('missing_sales_account', __('Sales account code is not configured.', 'cheapalarms'), ['status' => 500]);
        }
        
        foreach ($items as $item) {
            $unitAmount = (float)($item['amount'] ?? $item['unitAmount'] ?? 0);
            $quantity = (float)($item['qty'] ?? $item['quantity'] ?? 1);
            
            // Determine TaxType based on whether tax is included
            // For Australia GST: EXCLUSIVE = tax added, INCLUSIVE = tax included, NONE = no tax
            $taxType = 'NONE';
            if ($taxTotal > 0) {
                // If we have tax, use EXCLUSIVE (tax will be calculated by Xero)
                // Or use INCLUSIVE if tax is already included in the amount
                $taxType = $isTaxIncluded ? 'INCLUSIVE' : 'EXCLUSIVE';
            }
            
            // Validate line item data before adding
            if ($unitAmount < 0) {
                $this->logger->warning('Negative unit amount in invoice item', [
                    'item' => $item,
                    'unitAmount' => $unitAmount,
                ]);
                // Continue with the item but log the warning
            }
            
            if ($quantity <= 0) {
                $this->logger->warning('Invalid quantity in invoice item', [
                    'item' => $item,
                    'quantity' => $quantity,
                ]);
                // Set minimum quantity to 1
                $quantity = 1;
            }
            
            // Calculate LineAmount explicitly (Xero can calculate it, but providing it is clearer)
            $lineAmount = round($unitAmount * $quantity, 2);
            
            $lineItems[] = [
                'Description' => $item['description'] ?? $item['name'] ?? 'Item',
                'Quantity' => $quantity,
                'UnitAmount' => $unitAmount,
                'LineAmount' => $lineAmount, // Explicitly set LineAmount
                'AccountCode' => $salesAccountCode,
                'TaxType' => $taxType,
            ];
        }
        
        // Validate we have at least one line item
        if (empty($lineItems)) {
            return new WP_Error('no_line_items', __('Invoice must have at least one line item.', 'cheapalarms'), ['status' => 400]);
        }

        // Validate and format dates
        // Use stricter date parsing to avoid ambiguous dates
        $issueDate = $ghlInvoice['issueDate'] ?? null;
        if ($issueDate) {
            // Try multiple date formats
            $parsedDate = false;
            $dateFormats = ['Y-m-d', 'Y/m/d', 'd/m/Y', 'm/d/Y', 'Y-m-d H:i:s', 'Y-m-d\TH:i:s'];
            foreach ($dateFormats as $format) {
                $dateObj = \DateTime::createFromFormat($format, $issueDate);
                if ($dateObj !== false) {
                    $parsedDate = $dateObj->getTimestamp();
                    break;
                }
            }
            // Fallback to strtotime if DateTime parsing fails
            if ($parsedDate === false) {
                $parsedDate = strtotime($issueDate);
            }
            if ($parsedDate === false) {
                $issueDate = gmdate('Y-m-d');
            } else {
                $issueDate = gmdate('Y-m-d', $parsedDate);
            }
        } else {
            $issueDate = gmdate('Y-m-d');
        }
        
        $dueDate = $ghlInvoice['dueDate'] ?? null;
        if ($dueDate) {
            // Try multiple date formats
            $parsedDueDate = false;
            $dateFormats = ['Y-m-d', 'Y/m/d', 'd/m/Y', 'm/d/Y', 'Y-m-d H:i:s', 'Y-m-d\TH:i:s'];
            foreach ($dateFormats as $format) {
                $dateObj = \DateTime::createFromFormat($format, $dueDate);
                if ($dateObj !== false) {
                    $parsedDueDate = $dateObj->getTimestamp();
                    break;
                }
            }
            // Fallback to strtotime if DateTime parsing fails
            if ($parsedDueDate === false) {
                $parsedDueDate = strtotime($dueDate);
            }
            if ($parsedDueDate === false) {
                $dueDate = gmdate('Y-m-d', strtotime('+30 days', strtotime($issueDate)));
            } else {
                $dueDate = gmdate('Y-m-d', $parsedDueDate);
            }
        } else {
            $dueDate = gmdate('Y-m-d', strtotime('+30 days', strtotime($issueDate)));
        }
        
        // CRITICAL: Ensure DueDate is not before Date (Xero requirement)
        if ($dueDate < $issueDate) {
            $this->logger->warning('DueDate is before Date, adjusting to match Date', [
                'originalDueDate' => $dueDate,
                'issueDate' => $issueDate,
            ]);
            $dueDate = $issueDate; // Set to same as issue date
        }

        // Check for duplicate invoice by invoice number
        $invoiceNumber = $ghlInvoice['invoiceNumber'] ?? $ghlInvoice['number'] ?? null;
        if ($invoiceNumber) {
            // Validate invoice number format (Xero allows alphanumeric, max 50 chars typically)
            $invoiceNumber = trim($invoiceNumber);
            if (strlen($invoiceNumber) > 50) {
                $this->logger->warning('Invoice number exceeds 50 characters, truncating', [
                    'original' => $invoiceNumber,
                    'length' => strlen($invoiceNumber),
                ]);
                $invoiceNumber = substr($invoiceNumber, 0, 50);
            }
            // Remove any invalid characters (Xero typically allows alphanumeric, hyphens, underscores)
            $invoiceNumber = preg_replace('/[^a-zA-Z0-9\-_]/', '', $invoiceNumber);
            
            if (empty($invoiceNumber)) {
                // If invoice number becomes empty after sanitization, set to null
                $invoiceNumber = null;
            } else {
                $escapedNumber = str_replace('"', '""', $invoiceNumber);
                $whereClause = 'InvoiceNumber="' . $escapedNumber . '"';
                $existingInvoice = $this->makeRequest('GET', '/Invoices?where=' . urlencode($whereClause));
            
                if (!is_wp_error($existingInvoice) && !empty($existingInvoice['Invoices'])) {
                    $existing = $existingInvoice['Invoices'][0];
                    $this->logger->warning('Invoice already exists in Xero', [
                        'xeroInvoiceId' => $existing['InvoiceID'] ?? null,
                        'invoiceNumber' => $invoiceNumber,
                        'ghlInvoiceId' => $ghlInvoice['id'] ?? null,
                    ]);
                    return new WP_Error(
                        'duplicate_invoice',
                        __('Invoice with this number already exists in Xero.', 'cheapalarms'),
                        [
                            'status' => 409,
                            'xeroInvoiceId' => $existing['InvoiceID'] ?? null,
                            'invoiceNumber' => $invoiceNumber,
                        ]
                    );
                }
            }
        }

        // Determine invoice status
        // Xero valid statuses: DRAFT, SUBMITTED, AUTHORISED, PAID, VOIDED
        // Default to AUTHORISED for posted invoices, but allow DRAFT if specified
        $invoiceStatus = 'AUTHORISED';
        if (isset($ghlInvoice['status'])) {
            $ghlStatus = strtoupper($ghlInvoice['status']);
            // Map GHL status to Xero status
            if ($ghlStatus === 'DRAFT') {
                $invoiceStatus = 'DRAFT';
            } elseif (in_array($ghlStatus, ['SUBMITTED', 'PENDING'])) {
                $invoiceStatus = 'SUBMITTED';
            } elseif (in_array($ghlStatus, ['PAID', 'COMPLETED'])) {
                $invoiceStatus = 'PAID';
            } elseif ($ghlStatus === 'VOIDED' || $ghlStatus === 'CANCELLED') {
                $invoiceStatus = 'VOIDED';
            }
            // AUTHORISED is default for all other statuses
        }

        // Build Xero invoice
        // Note: CurrencyCode is intentionally omitted - Xero will automatically use
        // the organization's base currency. Setting a currency that the organization
        // is not subscribed to will cause a validation error.
        // LineAmountTypes: 'Exclusive' means tax is added on top, 'Inclusive' means tax is included
        // We use 'Exclusive' to match our TaxType logic (EXCLUSIVE for line items)
        $xeroInvoice = [
            'Type' => 'ACCREC', // Accounts Receivable
            'Contact' => [
                'ContactID' => $xeroContactId,
            ],
            'Date' => $issueDate,
            'DueDate' => $dueDate,
            'InvoiceNumber' => $invoiceNumber,
            'Reference' => 'GHL Invoice: ' . ($ghlInvoice['id'] ?? ''),
            'LineItems' => $lineItems,
            'LineAmountTypes' => 'Exclusive', // Required by Xero API - matches TaxType logic
            'Status' => $invoiceStatus, // DRAFT, SUBMITTED, AUTHORISED, PAID, or VOIDED
            // CurrencyCode omitted - Xero uses organization's base currency
        ];

        $result = $this->makeRequest('POST', '/Invoices', ['Invoices' => [$xeroInvoice]]);

        if (is_wp_error($result)) {
            return $result;
        }

        $invoice = $result['Invoices'][0] ?? null;
        if (!$invoice) {
            return new WP_Error('invoice_creation_failed', __('Failed to create invoice in Xero.', 'cheapalarms'), ['status' => 500]);
        }

        $this->logger->info('Invoice created in Xero', [
            'xeroInvoiceId' => $invoice['InvoiceID'],
            'invoiceNumber' => $invoice['InvoiceNumber'],
            'ghlInvoiceId' => $ghlInvoice['id'] ?? null,
        ]);

        return [
            'ok' => true,
            'invoice' => $invoice,
            'invoiceId' => $invoice['InvoiceID'],
            'invoiceNumber' => $invoice['InvoiceNumber'],
        ];
    }

    /**
     * Record payment in Xero
     * 
     * @param string $invoiceId Xero invoice ID
     * @param float $amount Payment amount
     * @param string $paymentMethod Payment method (e.g., 'Stripe')
     * @param string $transactionId External transaction ID
     * @return array|WP_Error
     */
    public function recordPayment(string $invoiceId, float $amount, string $paymentMethod = 'Stripe', string $transactionId = '')
    {
        // Get invoice to find account
        $invoiceResult = $this->makeRequest('GET', '/Invoices/' . $invoiceId);
        if (is_wp_error($invoiceResult)) {
            return $invoiceResult;
        }

        $invoice = $invoiceResult['Invoices'][0] ?? null;
        if (!$invoice) {
            return new WP_Error('invoice_not_found', __('Invoice not found in Xero.', 'cheapalarms'), ['status' => 404]);
        }

        // Check if invoice is DRAFT - Xero requires AUTHORISED status for payments
        $currentStatus = $invoice['Status'] ?? '';
        if ($currentStatus === 'DRAFT') {
            // Update invoice to AUTHORISED before recording payment
            $updateResult = $this->makeRequest('POST', '/Invoices/' . $invoiceId, [
                'Invoices' => [[
                    'InvoiceID' => $invoiceId,
                    'Status' => 'AUTHORISED',
                ]]
            ]);
            
            if (is_wp_error($updateResult)) {
                $this->logger->error('Failed to authorize invoice before payment', [
                    'invoiceId' => $invoiceId,
                    'error' => $updateResult->get_error_message(),
                ]);
                return new WP_Error('invoice_authorization_failed', __('Failed to authorize invoice. Please authorize it manually in Xero.', 'cheapalarms'), ['status' => 500]);
            }
            
            $this->logger->info('Invoice authorized before payment', [
                'invoiceId' => $invoiceId,
            ]);
            
            // Refresh invoice data after status update
            $invoiceResult = $this->makeRequest('GET', '/Invoices/' . $invoiceId);
            if (is_wp_error($invoiceResult)) {
                return $invoiceResult;
            }
            $invoice = $invoiceResult['Invoices'][0] ?? null;
        }

        // Validate payment amount
        $total = (float)($invoice['Total'] ?? 0);
        $amountPaid = (float)($invoice['AmountPaid'] ?? 0);
        $amountDue = $total - $amountPaid;
        
        if ($amount <= 0) {
            return new WP_Error('invalid_payment_amount', __('Payment amount must be greater than zero.', 'cheapalarms'), ['status' => 400]);
        }
        
        if ($amount > $amountDue) {
            return new WP_Error(
                'payment_exceeds_balance',
                sprintf(
                    __('Payment amount (%.2f) exceeds remaining balance (%.2f).', 'cheapalarms'),
                    $amount,
                    $amountDue
                ),
                [
                    'status' => 400,
                    'amount' => $amount,
                    'amountDue' => $amountDue,
                    'total' => $total,
                    'amountPaid' => $amountPaid,
                ]
            );
        }

        // Get bank account code from config
        // Can be configured via environment variable CA_XERO_BANK_ACCOUNT_CODE
        // or in secrets.php as 'xero_bank_account_code'
        $bankAccountCode = $this->config->getXeroBankAccountCode();
        
        // Validate bank account code
        if (empty($bankAccountCode)) {
            return new WP_Error('missing_bank_account', __('Bank account code is not configured.', 'cheapalarms'), ['status' => 500]);
        }
        
        // Validate payment date (must be valid date string)
        $paymentDate = gmdate('Y-m-d');
        
        // Create payment
        $payment = [
            'Invoice' => [
                'InvoiceID' => $invoiceId,
            ],
            'Account' => [
                'Code' => $bankAccountCode,
            ],
            'Date' => $paymentDate,
            'Amount' => round($amount, 2), // Ensure 2 decimal places
            'Reference' => trim($paymentMethod . ($transactionId ? ' - ' . $transactionId : '')),
        ];

        $result = $this->makeRequest('POST', '/Payments', ['Payments' => [$payment]]);

        if (is_wp_error($result)) {
            return $result;
        }

        $paymentRecord = $result['Payments'][0] ?? null;
        if (!$paymentRecord) {
            return new WP_Error('payment_creation_failed', __('Failed to record payment in Xero.', 'cheapalarms'), ['status' => 500]);
        }

        // After successful payment, check if invoice should be marked as PAID
        $newAmountPaid = $amountPaid + $amount;
        if (abs($newAmountPaid - $total) < 0.01) {
            // Payment covers full amount, update status to PAID
            $paidUpdateResult = $this->makeRequest('POST', '/Invoices/' . $invoiceId, [
                'Invoices' => [[
                    'InvoiceID' => $invoiceId,
                    'Status' => 'PAID',
                ]]
            ]);
            
            // Don't fail if status update fails - payment is already recorded
            if (is_wp_error($paidUpdateResult)) {
                $this->logger->warning('Payment recorded but failed to update invoice status to PAID', [
                    'invoiceId' => $invoiceId,
                    'error' => $paidUpdateResult->get_error_message(),
                ]);
            } else {
                $this->logger->info('Invoice status updated to PAID after full payment', [
                    'invoiceId' => $invoiceId,
                ]);
            }
        }

        $this->logger->info('Payment recorded in Xero', [
            'paymentId' => $paymentRecord['PaymentID'],
            'invoiceId' => $invoiceId,
            'amount' => $amount,
        ]);

        return [
            'ok' => true,
            'payment' => $paymentRecord,
            'paymentId' => $paymentRecord['PaymentID'],
        ];
    }

    /**
     * Encrypt sensitive token data before storage
     * 
     * @param array $tokens Token data to encrypt
     * @return string Encrypted token data
     */
    private function encryptTokens(array $tokens): string
    {
        $key = hash('sha256', wp_salt('xero_tokens'));
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt(
            json_encode($tokens),
            'aes-256-cbc',
            $key,
            0,
            $iv
        );
        
        if ($encrypted === false) {
            $this->logger->error('Failed to encrypt Xero tokens');
            // Fallback to base64 encoding if encryption fails
            return base64_encode(json_encode($tokens));
        }
        
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt token data from storage
     * 
     * @param string $encrypted Encrypted token data
     * @return array|null Decrypted token data or null on failure
     */
    private function decryptTokens(string $encrypted): ?array
    {
        $data = base64_decode($encrypted, true);
        if ($data === false) {
            // Try to decode as plain JSON (backward compatibility for unencrypted tokens)
            $decoded = json_decode($encrypted, true);
            if (is_array($decoded)) {
                return $decoded;
            }
            return null;
        }
        
        $key = hash('sha256', wp_salt('xero_tokens'));
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($data, 0, $ivLength);
        $encryptedData = substr($data, $ivLength);
        
        $decrypted = openssl_decrypt(
            $encryptedData,
            'aes-256-cbc',
            $key,
            0,
            $iv
        );
        
        if ($decrypted === false) {
            // Try to decode as plain JSON (backward compatibility for old base64-encoded JSON)
            $decoded = json_decode($encryptedData, true);
            if (is_array($decoded)) {
                return $decoded;
            }
            return null;
        }
        
        $tokens = json_decode($decrypted, true);
        return is_array($tokens) ? $tokens : null;
    }

    /**
     * Store tokens securely (encrypted)
     * 
     * @param array $tokens Token data
     * @return void
     */
    private function storeTokens(array $tokens): void
    {
        $encrypted = $this->encryptTokens($tokens);
        update_option(self::TOKEN_OPTION_KEY, $encrypted);
    }

    /**
     * Get tokens from storage (decrypted)
     * 
     * @return array|null Token data or null if not found/invalid
     */
    private function getTokens(): ?array
    {
        $encrypted = get_option(self::TOKEN_OPTION_KEY);
        if (empty($encrypted)) {
            return null;
        }
        
        // Handle both encrypted and plain storage (backward compatibility)
        if (is_array($encrypted)) {
            return $encrypted;
        }
        
        return $this->decryptTokens($encrypted);
    }

    /**
     * Check if Xero is connected
     * 
     * @return bool
     */
    public function isConnected(): bool
    {
        $tokens = $this->getTokens();
        return !empty($tokens['access_token']);
    }

    /**
     * Disconnect Xero (clear tokens)
     * 
     * @return bool
     */
    public function disconnect(): bool
    {
        delete_option(self::TOKEN_OPTION_KEY);
        delete_option(self::TENANT_OPTION_KEY);
        delete_transient(self::REFRESH_LOCK_KEY);
        return true;
    }
}

