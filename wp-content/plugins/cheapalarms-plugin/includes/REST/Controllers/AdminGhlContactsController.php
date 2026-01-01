<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Services\Logger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function is_array;
use function is_wp_error;
use function rawurlencode;
use function sanitize_text_field;
use function wp_generate_password;
use function wp_get_current_user;

/**
 * Admin-only endpoints for destructive GHL operations.
 */
class AdminGhlContactsController extends AdminController
{
    private Authenticator $auth;
    private GhlClient $ghlClient;
    private Logger $logger;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->auth = $this->container->get(Authenticator::class);
        $this->ghlClient = $this->container->get(GhlClient::class);
        $this->logger = $this->container->get(Logger::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/admin/ghl/contacts/(?P<contactId>[a-zA-Z0-9]+)/delete', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->deleteContact($request);
            },
            'args'                => [
                'contactId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);
    }

    /**
     * POST /ca/v1/admin/ghl/contacts/{contactId}/delete
     * Deletes a GHL contact only (no local deletion).
     */
    public function deleteContact(WP_REST_Request $request): WP_REST_Response
    {
        // Safety gate
        $gate = $this->checkDestructiveActionsEnabled();
        if ($gate) {
            return $this->respond($gate);
        }

        $contactId = sanitize_text_field($request->get_param('contactId') ?? '');
        $body = $request->get_json_params();
        if (!is_array($body)) {
            $body = [];
        }

        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $locationIdRaw = sanitize_text_field($body['locationId'] ?? ($request->get_param('locationId') ?? ''));
        $locationIdResult = $this->locationResolver->resolveOrError(!empty($locationIdRaw) ? $locationIdRaw : null);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        if (empty($contactId)) {
            return $this->respond(new WP_Error('bad_request', __('contactId is required.', 'cheapalarms'), ['status' => 400]));
        }

        if ($confirm !== 'DELETE') {
            return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="DELETE" in request body.', 'cheapalarms'), ['status' => 400]));
        }

        $user = wp_get_current_user();
        $correlationId = wp_generate_password(12, false);

        $this->logger->info('GHL contact delete initiated', [
            'correlationId' => $correlationId,
            'contactId' => $contactId,
            'locationId' => $locationId,
            'userId' => $user->ID ?? null,
            'userEmail' => $user->user_email ?? null,
        ]);

        $result = [
            'ok' => true,
            'scope' => 'ghl',
            'correlationId' => $correlationId,
            'ghl' => ['ok' => false, 'skipped' => true],
        ];

        // GHL delete: DELETE /contacts/{contactId}
        // Per docs: https://marketplace.gohighlevel.com/docs/ghl/contacts/delete-contact/index.html
        // We pass location context via both query param and LocationId header.
        $ghlResult = $this->ghlClient->delete(
            '/contacts/' . rawurlencode($contactId),
            ['locationId' => $locationId],
            $locationId,
            10,
            0
        );

        if (is_wp_error($ghlResult)) {
            $errorData = $ghlResult->get_error_data();
            $result['ghl'] = [
                'ok' => false,
                'error' => $ghlResult->get_error_message(),
                'code' => $ghlResult->get_error_code(),
                'httpCode' => is_array($errorData) ? ($errorData['code'] ?? null) : null,
            ];
            $result['ok'] = false;

            $this->logger->warning('GHL contact delete failed', [
                'correlationId' => $correlationId,
                'contactId' => $contactId,
                'locationId' => $locationId,
                'ghlError' => $ghlResult->get_error_message(),
            ]);

            return $this->respond(new WP_Error(
                'delete_partial_failure',
                'Delete operation completed with errors.',
                ['status' => 500, 'details' => $result]
            ));
        }

        $result['ghl'] = [
            'ok' => true,
            'alreadyDeleted' => $ghlResult['alreadyDeleted'] ?? false,
        ];

        $this->logger->info('GHL contact deleted', [
            'correlationId' => $correlationId,
            'contactId' => $contactId,
            'alreadyDeleted' => $result['ghl']['alreadyDeleted'],
        ]);

        return $this->respond($result);
    }
}


