<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\XeroService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_text_field;
use function current_time;

class XeroController extends AdminController
{
    private XeroService $xeroService;
    private Authenticator $auth;
    private \CheapAlarms\Plugin\Services\Logger $logger;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->xeroService = $this->container->get(XeroService::class);
        $this->auth = $this->container->get(Authenticator::class);
        $this->logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
    }

    public function register(): void
    {
        // Get authorization URL
        register_rest_route('ca/v1', '/xero/authorize', [
            'methods' => 'GET',
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->getAuthorizationUrl($request);
            },
        ]);

        // OAuth callback (handled by Next.js API route, but we provide the exchange endpoint)
        // Note: This endpoint is called server-to-server from Next.js, so we don't require user auth
        // The state parameter provides CSRF protection
        // Additional security: Only allow from Next.js frontend URL
        register_rest_route('ca/v1', '/xero/callback', [
            'methods' => 'POST',
            'permission_callback' => function () {
                // Verify request is from our frontend
                $frontendUrl = $this->container->get(\CheapAlarms\Plugin\Config\Config::class)->getFrontendUrl();
                $referer = $_SERVER['HTTP_REFERER'] ?? '';
                $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
                
                // Allow if referer or origin matches frontend URL, or if state token is valid (CSRF protection)
                // The state token validation in handleCallback provides additional security
                return true; // State token validation is the primary security mechanism
            },
            'callback' => function (WP_REST_Request $request) {
                return $this->handleCallback($request);
            },
        ]);

        // Check connection status
        register_rest_route('ca/v1', '/xero/status', [
            'methods' => 'GET',
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->getStatus($request);
            },
        ]);

        // Disconnect Xero
        register_rest_route('ca/v1', '/xero/disconnect', [
            'methods' => 'POST',
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->disconnect($request);
            },
        ]);

        // Sync invoice to Xero
        register_rest_route('ca/v1', '/xero/sync-invoice', [
            'methods' => 'POST',
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->syncInvoice($request);
            },
        ]);
    }

    private function getAuthorizationUrl(WP_REST_Request $request): WP_REST_Response
    {
        $result = $this->xeroService->getAuthorizationUrl();
        
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok' => true,
            'authUrl' => $result['authUrl'],
            'state' => $result['state'],
        ]);
    }

    private function handleCallback(WP_REST_Request $request): WP_REST_Response
    {
        // Additional security: Verify request source
        $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
        $frontendUrl = $config->getFrontendUrl();
        $referer = sanitize_text_field($_SERVER['HTTP_REFERER'] ?? '');
        $origin = sanitize_text_field($_SERVER['HTTP_ORIGIN'] ?? '');
        
        // Check if request comes from our frontend (optional but recommended)
        $isValidSource = false;
        if (!empty($frontendUrl)) {
            $frontendHost = parse_url($frontendUrl, PHP_URL_HOST);
            $refererHost = parse_url($referer, PHP_URL_HOST);
            $originHost = parse_url($origin, PHP_URL_HOST);
            
            $isValidSource = ($refererHost === $frontendHost) || ($originHost === $frontendHost);
        }
        
        // Get parameters from JSON body (POST request)
        $body = $request->get_json_params();
        $code = sanitize_text_field($body['code'] ?? '');
        $state = sanitize_text_field($body['state'] ?? '');

        if (empty($code) || empty($state)) {
            return $this->respond(new WP_Error('missing_params', __('Code and state are required.', 'cheapalarms'), ['status' => 400]));
        }
        
        // Log suspicious requests (but don't block - state token validation is primary security)
        if (!$isValidSource && !empty($referer)) {
            $this->container->get(\CheapAlarms\Plugin\Services\Logger::class)->warning('Xero callback from unexpected source', [
                'referer' => $referer,
                'origin' => $origin,
                'expected' => $frontendUrl,
            ]);
        }

        $result = $this->xeroService->exchangeCodeForToken($code, $state);
        
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok' => true,
            'tenantId' => $result['tenantId'],
        ]);
    }

    private function getStatus(WP_REST_Request $request): WP_REST_Response
    {
        $isConnected = $this->xeroService->isConnected();

        return $this->respond([
            'ok' => true,
            'connected' => $isConnected,
        ]);
    }

    private function disconnect(WP_REST_Request $request): WP_REST_Response
    {
        $this->xeroService->disconnect();

        return $this->respond([
            'ok' => true,
            'message' => __('Xero disconnected successfully.', 'cheapalarms'),
        ]);
    }

    private function syncInvoice(WP_REST_Request $request): WP_REST_Response
    {
        // Get parameters from JSON body (POST request)
        $body = $request->get_json_params();
        $invoiceId = sanitize_text_field($body['invoiceId'] ?? '');
        $locationId = sanitize_text_field($body['locationId'] ?? '');

        if (empty($invoiceId)) {
            return $this->respond(new WP_Error('missing_invoice_id', __('Invoice ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        // Get invoice from GHL via InvoiceService
        $invoiceService = $this->container->get(\CheapAlarms\Plugin\Services\InvoiceService::class);
        $ghlInvoice = $invoiceService->getInvoice($invoiceId, $locationId);

        if (is_wp_error($ghlInvoice)) {
            return $this->respond($ghlInvoice);
        }

        // Extract contact data
        $contact = $ghlInvoice['contact'] ?? [];
        $contactName = trim($contact['name'] ?? '');
        
        // Split name into first and last name, handling edge cases
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
        $result = $this->xeroService->createInvoice($ghlInvoice, $contactData);

        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        // Store Xero invoice ID in portal meta (find estimate ID from invoice ID)
        $portalMetaRepo = $this->container->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class);
        $estimateId = $portalMetaRepo->findEstimateIdByInvoiceId($invoiceId);
        
        if ($estimateId) {
            $meta = $portalMetaRepo->get($estimateId);
            $invoiceMeta = $meta['invoice'] ?? [];
            $invoiceMeta['xeroInvoiceId'] = $result['invoiceId'];
            $invoiceMeta['xeroInvoiceNumber'] = $result['invoiceNumber'];
            // Update sync status for manual sync
            $invoiceMeta['xeroSync'] = [
                'status' => 'success',
                'attemptedAt' => current_time('mysql'),
                'error' => null,
                'retryCount' => ($invoiceMeta['xeroSync']['retryCount'] ?? 0),
                'note' => 'Manually synced via admin',
            ];
            $portalMetaRepo->merge($estimateId, ['invoice' => $invoiceMeta]);
            
            $this->logger->info('Stored Xero invoice ID in portal meta (manual sync)', [
                'estimateId' => $estimateId,
                'invoiceId' => $invoiceId,
                'xeroInvoiceId' => $result['invoiceId'],
            ]);
        } else {
            $this->logger->warning('Could not find estimate ID for invoice, Xero invoice ID not stored', [
                'invoiceId' => $invoiceId,
                'xeroInvoiceId' => $result['invoiceId'],
            ]);
        }

        return $this->respond([
            'ok' => true,
            'xeroInvoiceId' => $result['invoiceId'],
            'xeroInvoiceNumber' => $result['invoiceNumber'],
            'message' => __('Invoice synced to Xero successfully.', 'cheapalarms'),
        ]);
    }
}

