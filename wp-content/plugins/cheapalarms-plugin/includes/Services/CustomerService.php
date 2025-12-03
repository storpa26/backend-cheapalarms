<?php

namespace CheapAlarms\Plugin\Services;

use WP_Error;
use WP_User;

use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Services\Logger;

use function email_exists;
use function get_password_reset_key;
use function get_user_by;
use function sanitize_email;
use function sanitize_text_field;
use function update_user_meta;
use function wp_create_user;
use function wp_generate_password;
use function wp_login_url;
use function wp_mail;
use function wp_update_user;
use function add_query_arg;

class CustomerService
{
    public function __construct(
        private GhlClient $ghlClient,
        private Logger $logger
    ) {
    }

    /**
     * Links a GHL contact to a WordPress user
     * Stores ghl_contact_id in user meta
     */
    public function linkGhlContact(int $userId, string $ghlContactId): bool
    {
        $result = update_user_meta($userId, 'ghl_contact_id', sanitize_text_field($ghlContactId));
        return $result !== false;
    }

    /**
     * Creates WordPress user from GHL contact
     * Returns user ID or WP_Error
     */
    public function createUserFromGhlContact(array $ghlContact): int|WP_Error
    {
        $email = sanitize_email($ghlContact['email'] ?? '');
        if (!$email) {
            return new WP_Error('no_email', 'GHL contact must have email to create WordPress user');
        }

        // Check if user already exists
        $userId = email_exists($email);
        if ($userId) {
            return $userId; // User already exists
        }

        // Create user
        $password = wp_generate_password(20);
        $userId = wp_create_user($email, $password, $email);
        if (is_wp_error($userId)) {
            return $userId;
        }

        // Update user details
        wp_update_user([
            'ID' => $userId,
            'first_name' => sanitize_text_field($ghlContact['firstName'] ?? ''),
            'last_name' => sanitize_text_field($ghlContact['lastName'] ?? ''),
            'role' => 'customer',
        ]);

        // Link GHL contact
        if (!empty($ghlContact['id'])) {
            update_user_meta($userId, 'ghl_contact_id', sanitize_text_field($ghlContact['id']));
        }

        $this->logger->info('WordPress user created from GHL contact', [
            'userId' => $userId,
            'email' => $email,
            'ghlContactId' => $ghlContact['id'] ?? null,
        ]);

        return $userId;
    }

    /**
     * Sends portal invite to GHL contact (without estimate requirement)
     * Creates WP user if needed, sends password reset link
     */
    public function inviteGhlContactToPortal(string $ghlContactId, array $ghlContact): array|WP_Error
    {
        $email = sanitize_email($ghlContact['email'] ?? '');
        if (!$email) {
            return new WP_Error('no_email', 'GHL contact must have email to receive portal invite');
        }

        // Create or get WP user
        $userId = email_exists($email);
        if (!$userId) {
            $result = $this->createUserFromGhlContact($ghlContact);
            if (is_wp_error($result)) {
                return $result;
            }
            $userId = $result;
        } else {
            // Ensure user has customer role
            $user = get_user_by('id', $userId);
            if ($user && !in_array('customer', $user->roles, true)) {
                wp_update_user(['ID' => $userId, 'role' => 'customer']);
            }
        }

        // Link GHL contact
        $this->linkGhlContact($userId, $ghlContactId);

        // Send password reset email with portal link
        $user = get_user_by('id', $userId);
        if (!$user) {
            return new WP_Error('user_not_found', 'Failed to retrieve user after creation');
        }

        $key = get_password_reset_key($user);
        $resetUrl = null;
        if (!is_wp_error($key)) {
            $resetUrl = add_query_arg(
                [
                    'action' => 'rp',
                    'key' => $key,
                    'login' => rawurlencode($user->user_login),
                ],
                wp_login_url()
            );
        }

        $portalUrl = home_url('/portal');
        $firstName = sanitize_text_field($ghlContact['firstName'] ?? 'Customer');
        $lastName = sanitize_text_field($ghlContact['lastName'] ?? '');
        $name = trim($firstName . ' ' . $lastName) ?: 'Customer';

        $subject = __('Your CheapAlarms portal is ready', 'cheapalarms');
        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $greeting = sprintf(__('Hi %s,', 'cheapalarms'), $name);

        $body = '<p>' . esc_html($greeting) . '</p>';
        $body .= '<p>' . esc_html(__('We have prepared your CheapAlarms portal. Use the link below to set your password and access your portal.', 'cheapalarms')) . '</p>';
        $body .= '<p><a href="' . esc_url($portalUrl) . '">' . esc_html(__('Access your portal', 'cheapalarms')) . '</a></p>';

        if ($resetUrl) {
            $body .= '<p><a href="' . esc_url($resetUrl) . '">' . esc_html(__('Set or reset your password', 'cheapalarms')) . '</a></p>';
        } else {
            $body .= '<p>' . esc_html(__('If you need to reset your password, use the "Forgot password?" link on the login page.', 'cheapalarms')) . '</p>';
        }

        $body .= '<p>' . esc_html(__('Thanks,', 'cheapalarms')) . '<br />' . esc_html(__('CheapAlarms Team', 'cheapalarms')) . '</p>';

        // Send via GHL
        $sent = false;
        if ($ghlContactId) {
            $ghlClient = $this->container->get(GhlClient::class);
            $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
            $fromEmail = get_option('ghl_from_email', 'quotes@cheapalarms.com.au');
            
            $payload = [
                'contactId' => $ghlContactId,
                'type' => 'Email',
                'status' => 'pending',
                'subject' => $subject,
                'html' => $body,
                'emailFrom' => $fromEmail,
            ];
            
            if ($config->getLocationId()) {
                $payload['locationId'] = $config->getLocationId();
            }
            
            $result = $ghlClient->post('/conversations/messages', $payload);
            $sent = !is_wp_error($result);
        }

        $this->logger->info('Portal invite sent to GHL contact via GHL email', [
            'ghlContactId' => $ghlContactId,
            'userId' => $userId,
            'email' => $email,
            'sentViaGhl' => $sent,
        ]);

        return [
            'ok' => true,
            'userId' => $userId,
            'inviteSent' => $sent,
            'resetUrl' => $resetUrl,
        ];
    }

    /**
     * Matches GHL contact to existing WP user by email
     * Returns WP user ID or null
     */
    public function findMatchingUser(string $email, ?string $phone = null): ?int
    {
        // Try email first (primary match)
        if ($email) {
            $userId = email_exists($email);
            if ($userId) {
                return $userId;
            }
        }

        // Phone matching could be added here later if needed
        // For now, email-only matching is sufficient

        return null;
    }
}

