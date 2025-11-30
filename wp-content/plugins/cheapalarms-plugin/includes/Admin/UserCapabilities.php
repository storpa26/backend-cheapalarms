<?php

namespace CheapAlarms\Plugin\Admin;

use function add_action;
use function current_user_can;
use function esc_attr;
use function esc_html;
use function esc_html_e;
use function get_userdata;
use function in_array;
use function is_array;
use function wp_get_current_user;

class UserCapabilities
{
    public function __construct()
    {
        add_action('show_user_profile', [$this, 'renderUserCapabilities']);
        add_action('edit_user_profile', [$this, 'renderUserCapabilities']);
        add_action('personal_options_update', [$this, 'saveUserCapabilities']);
        add_action('edit_user_profile_update', [$this, 'saveUserCapabilities']);
    }

    /**
     * Render capabilities meta box on user edit screen
     */
    public function renderUserCapabilities(\WP_User $user): void
    {
        // Only show to users who can promote users
        if (!current_user_can('promote_users')) {
            return;
        }

        $capabilities = [
            'ca_manage_portal'    => 'Manage Portal (Admin access to estimates/invoices)',
            'ca_manage_support'    => 'Manage Support',
            'ca_view_estimates'    => 'View Estimates',
            'ca_invite_customers'  => 'Invite Customers',
            'ca_access_portal'     => 'Access Portal',
        ];

        // Check individual user capabilities (not role-based)
        // $user->caps contains individual capabilities granted directly to the user
        $userCaps = $user->caps ?? [];
        
        // Also check if user has these via their role (for display purposes)
        $userAllCaps = $user->allcaps ?? [];
        $isAdmin = in_array('administrator', $user->roles ?? [], true);
        ?>
        <h2><?php esc_html_e('CheapAlarms Capabilities', 'cheapalarms'); ?></h2>
        <table class="form-table">
            <tr>
                <th>
                    <label><?php esc_html_e('Capabilities', 'cheapalarms'); ?></label>
                </th>
                <td>
                    <fieldset>
                        <legend class="screen-reader-text">
                            <span><?php esc_html_e('CheapAlarms Capabilities', 'cheapalarms'); ?></span>
                        </legend>
                        <?php foreach ($capabilities as $cap => $label): ?>
                            <?php
                            // Check if user has this capability individually OR via role
                            $hasCap = isset($userCaps[$cap]) && $userCaps[$cap];
                            $hasViaRole = isset($userAllCaps[$cap]) && $userAllCaps[$cap];
                            $isChecked = $hasCap || $hasViaRole;
                            $isDisabled = $isAdmin && !$hasCap; // Disable if admin has it via role only
                            ?>
                            <label for="ca_cap_<?php echo esc_attr($cap); ?>">
                                <input
                                    type="checkbox"
                                    name="ca_capabilities[]"
                                    id="ca_cap_<?php echo esc_attr($cap); ?>"
                                    value="<?php echo esc_attr($cap); ?>"
                                    <?php checked($isChecked); ?>
                                    <?php disabled($isDisabled); ?>
                                />
                                <?php echo esc_html($label); ?>
                                <?php if ($isAdmin && !$hasCap && $hasViaRole): ?>
                                    <span class="description" style="margin-left: 8px;">(via Administrator role)</span>
                                <?php endif; ?>
                            </label>
                            <br />
                        <?php endforeach; ?>
                        <p class="description">
                            <?php esc_html_e('Grant specific CheapAlarms capabilities to this user. Administrators automatically have all capabilities via their role.', 'cheapalarms'); ?>
                        </p>
                    </fieldset>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Save user capabilities
     */
    public function saveUserCapabilities(int $userId): void
    {
        // Only allow users who can promote users
        if (!current_user_can('promote_users')) {
            return;
        }

        // Don't allow editing your own capabilities (security)
        $currentUser = wp_get_current_user();
        if ($currentUser->ID === $userId && !current_user_can('manage_options')) {
            return;
        }

        $user = get_userdata($userId);
        if (!$user) {
            return;
        }

        // Check if user is administrator (they get all caps via role)
        $isAdmin = in_array('administrator', $user->roles ?? [], true);
        if ($isAdmin) {
            // Administrators get all capabilities via role, no need to save individual caps
            return;
        }

        $selectedCaps = $_POST['ca_capabilities'] ?? [];
        if (!is_array($selectedCaps)) {
            $selectedCaps = [];
        }

        $allCaps = [
            'ca_manage_portal',
            'ca_manage_support',
            'ca_view_estimates',
            'ca_invite_customers',
            'ca_access_portal',
        ];

        // Update user capabilities
        foreach ($allCaps as $cap) {
            if (in_array($cap, $selectedCaps, true)) {
                $user->add_cap($cap);
            } else {
                // Remove capability if not selected
                $user->remove_cap($cap);
            }
        }
    }
}

