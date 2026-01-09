<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Services\UserContextHelper;
use CheapAlarms\Plugin\Config\Config;

/**
 * Service for rendering context-aware email templates
 */
class EmailTemplateService
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Render quote request email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, portalUrl, resetUrl, loginUrl)
     * @param string|null $variation Override variation (A, B, C, D) or null to auto-detect
     * @return array ['subject' => string, 'body' => string]
     */
    public function renderQuoteRequestEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('quote-request', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        // Fallback if estimate number is empty
        if (empty($estimateNumber)) {
            $estimateNumber = __('your quote', 'cheapalarms');
        }
        $portalUrl = $data['portalUrl'] ?? '';
        $resetUrl = $data['resetUrl'] ?? '';
        $loginUrl = $data['loginUrl'] ?? $this->config->getFrontendUrl() . '/login';
        
        $isNewUser = $context['isNewUser'] ?? false;
        $hasPasswordSet = $context['hasPasswordSet'] ?? false;
        $hasPreviousEstimates = $context['hasPreviousEstimates'] ?? false;
        $estimateCount = $context['estimateCount'] ?? 0; // Previous estimates count (for variation detection)
        $totalEstimateCount = $context['totalEstimateCount'] ?? ($estimateCount + 1); // Total count for display

        switch ($variation) {
            case 'A': // New Customer, First Quote
                $subject = __('Welcome! Your CheapAlarms quote is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Welcome to CheapAlarms! We\'re excited to help secure your property.', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('We\'ve prepared your personalized quote %s based on your requirements. To access your quote and set up your account, please set a password using the link below.', 'cheapalarms'),
                    '<strong>' . esc_html($estimateNumber) . '</strong>'
                ) . '</p>';
                $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Once you\'ve set your password, you\'ll be able to view your quote, accept it, and track your installation progress.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View as Guest', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // Returning Customer, Has Password
                $subject = sprintf(__('Your new quote %s is ready', 'cheapalarms'), $estimateNumber);
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Great to have you back! We\'ve prepared a new quote for you.', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('Your new quote %s is ready for review.', 'cheapalarms'),
                    '<strong>' . esc_html($estimateNumber) . '</strong>'
                );
                if ($totalEstimateCount > 1) {
                    $body .= ' ' . esc_html(sprintf(
                        __('This is your %s quote with us.', 'cheapalarms'),
                        $totalEstimateCount === 2 ? __('second', 'cheapalarms') : sprintf(__('%dth', 'cheapalarms'), $totalEstimateCount)
                    ));
                }
                $body .= '</p>';
                $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Simply log in to your portal to view and manage this quote.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View Your Quote', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($loginUrl)) {
                    $ctas[] = ['href' => $loginUrl, 'text' => __('Login to Portal', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'C': // Returning Customer, No Password
                // Check if this is their second quote (1 previous + 1 current)
                $isSecondQuote = ($totalEstimateCount === 2);
                
                if ($isSecondQuote) {
                    // Special messaging for second quote scenario
                    $subject = sprintf(__('Your second quote %s is ready', 'cheapalarms'), $estimateNumber);
                    $body = $this->getEmailHeader();
                    $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                    $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                    $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                    $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve prepared another quote for you!', 'cheapalarms')) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                        __('This is your second quote with us. Your new quote %s is ready for review. You also have a previous quote waiting.', 'cheapalarms'),
                        '<strong>' . esc_html($estimateNumber) . '</strong>'
                    ) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('To access both quotes and manage your account, please set a password using the link below.', 'cheapalarms')) . '</p>';
                    $body .= '</div>';
                } else {
                    // Original messaging for other cases (shouldn't happen often, but keep as fallback)
                    $subject = sprintf(__('Your new quote %s is ready', 'cheapalarms'), $estimateNumber);
                    $body = $this->getEmailHeader();
                    $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                    $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                    $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                    $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve prepared a new quote for you!', 'cheapalarms')) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                        __('Your new quote %s is ready for review. To access it, please set a password for your account using the link below.', 'cheapalarms'),
                        '<strong>' . esc_html($estimateNumber) . '</strong>'
                    ) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Once you\'ve set your password, you\'ll be able to view your quote and manage your account.', 'cheapalarms')) . '</p>';
                    $body .= '</div>';
                }
                
                // Common CTAs for both cases
                $ctas = [];
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View as Guest', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'D': // Customer with Multiple Estimates
            default:
                // Check if password is set - affects messaging and CTAs
                if (!$hasPasswordSet) {
                    // Multiple quotes but no password - guest access is limited to current quote only
                    $subject = __('Another quote ready for you', 'cheapalarms');
                    $body = $this->getEmailHeader();
                    $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                    $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                    $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                    $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve prepared another quote for you!', 'cheapalarms')) . '</p>';
                    // Defensive check: ensure totalEstimateCount is at least 2 before showing count
                    $safeTotalCount = max(2, $totalEstimateCount);
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                        __('Your new quote %s is ready. This is your %s quote with us.', 'cheapalarms'),
                        '<strong>' . esc_html($estimateNumber) . '</strong>',
                        $safeTotalCount === 2 ? __('second', 'cheapalarms') : ($safeTotalCount === 3 ? __('third', 'cheapalarms') : sprintf(__('%dth', 'cheapalarms'), $safeTotalCount))
                    ) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('To access all your quotes and manage your account, please set a password using the link below. You can also view this quote as a guest.', 'cheapalarms')) . '</p>';
                    $body .= '</div>';
                    $ctas = [];
                    if (!empty($resetUrl)) {
                        $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => true];
                    }
                    if (!empty($portalUrl)) {
                        $ctas[] = ['href' => $portalUrl, 'text' => __('View as Guest', 'cheapalarms'), 'primary' => false];
                    }
                    if (!empty($ctas)) {
                        $body .= $this->getCTAs($ctas);
                    }
                    $body .= '</div>';
                    $body .= $this->getEmailFooter();
                } else {
                    // Original Variation D logic (has password - can see all quotes)
                    $subject = __('Another quote ready for you', 'cheapalarms');
                    $body = $this->getEmailHeader();
                    $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                    $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                    $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                    $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve prepared another quote for you!', 'cheapalarms')) . '</p>';
                    // Defensive check: ensure totalEstimateCount is at least 2 before showing count
                    $safeTotalCount = max(2, $totalEstimateCount);
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                        __('Your new quote %s is ready. This is your %s quote with us.', 'cheapalarms'),
                        '<strong>' . esc_html($estimateNumber) . '</strong>',
                        $safeTotalCount === 2 ? __('second', 'cheapalarms') : ($safeTotalCount === 3 ? __('third', 'cheapalarms') : sprintf(__('%dth', 'cheapalarms'), $safeTotalCount))
                    ) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('You can view this quote and all your previous estimates in your portal.', 'cheapalarms')) . '</p>';
                    $body .= '</div>';
                    $ctas = [];
                    if (!empty($portalUrl)) {
                        $ctas[] = ['href' => $portalUrl, 'text' => __('View New Quote', 'cheapalarms'), 'primary' => true];
                    }
                    if (!empty($loginUrl)) {
                        $ctas[] = ['href' => $loginUrl, 'text' => __('Login to Portal', 'cheapalarms'), 'primary' => false];
                    }
                    if (!empty($ctas)) {
                        $body .= $this->getCTAs($ctas);
                    }
                    $body .= '</div>';
                    $body .= $this->getEmailFooter();
                }
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render password reset email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, resetUrl)
     * @param string|null $variation Override variation (A, B) or null to auto-detect
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderPasswordResetEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('password-reset', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $resetUrl = $data['resetUrl'] ?? '';
        
        $isNewUser = $context['isNewUser'] ?? false;
        $hasPasswordSet = $context['hasPasswordSet'] ?? false;
        
        switch ($variation) {
            case 'A': // New User, First Time Setting Password
                $subject = __('Set Your Password - CheapAlarms Portal', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Welcome to CheapAlarms! To access your portal and view your quote, please set a password for your account.', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Click the button below to set your password. This link will expire in 24 hours.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('Or copy and paste this link into your browser:', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 10px 0 0 0; color: #666666; font-size: 12px; word-break: break-all;">' . esc_html($resetUrl) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // Returning User, Password Reset
            default:
                $subject = __('Reset Your Password - CheapAlarms Portal', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We received a request to reset your password. Click the button below to set a new password for your account.', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('If you didn\'t request this, you can safely ignore this email. This link will expire in 24 hours.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Reset Password', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('Or copy and paste this link into your browser:', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 10px 0 0 0; color: #666666; font-size: 12px; word-break: break-all;">' . esc_html($resetUrl) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render portal invite email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, portalUrl, resetUrl, isResend, estimateNumber)
     * @param string|null $variation Override variation (A, B, C, D, E) or null to auto-detect
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderPortalInviteEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('portal-invite', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $portalUrl = $data['portalUrl'] ?? '';
        $resetUrl = $data['resetUrl'] ?? '';
        $isResend = $data['isResend'] ?? false;
        $estimateNumber = $data['estimateNumber'] ?? '';
        
        $isNewUser = $context['isNewUser'] ?? false;
        $hasPasswordSet = $context['hasPasswordSet'] ?? false;
        $hasPreviousEstimates = $context['hasPreviousEstimates'] ?? false;
        $totalEstimateCount = $context['totalEstimateCount'] ?? 1;

        switch ($variation) {
            case 'A': // New User, No Password, First Quote
                $subject = $isResend 
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We have prepared your CheapAlarms portal. Use the secure links below to access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // New User, Has Password, First Quote
                $subject = $isResend 
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your CheapAlarms portal is ready! You can access your estimate and manage your installation.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'C': // Returning User, Has Password
                $subject = $isResend 
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Great to have you back! Your portal is ready with your latest estimate.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'D': // Returning User, No Password
                $subject = $isResend 
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We have prepared your CheapAlarms portal. To access it, please set a password for your account.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'E': // Customer with Multiple Estimates
            default:
                $subject = $isResend 
                    ? __('CheapAlarms portal invite (resent)', 'cheapalarms')
                    : __('Your CheapAlarms portal is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                
                // Check password status for appropriate messaging (using method-level variable from line 330)
                if (!$hasPasswordSet) {
                    // Multiple estimates but no password - need to set password to access all
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your portal is ready with your latest estimate. You can view all your estimates and manage your installations in one place.', 'cheapalarms')) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Please set a password using the link below to access all your estimates and manage your account.', 'cheapalarms')) . '</p>';
                } else {
                    // Has password - can login to see all estimates
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your portal is ready with your latest estimate. You can view all your estimates and manage your installations in one place.', 'cheapalarms')) . '</p>';
                    $body .= '<p style="margin: 0 0 20px 0; line-height: 1.6;">' . esc_html(__('Simply log in to your portal to access all your estimates.', 'cheapalarms')) . '</p>';
                }
                $body .= '</div>';
                $ctas = [];
                if (!$hasPasswordSet && !empty($resetUrl)) {
                    // No password - show password setup as primary CTA
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => true];
                    if (!empty($portalUrl)) {
                        $ctas[] = ['href' => $portalUrl, 'text' => __('View as Guest', 'cheapalarms'), 'primary' => false];
                    }
                } elseif ($hasPasswordSet && !empty($portalUrl)) {
                    // Has password - show portal/login CTAs
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                    $loginUrl = $data['loginUrl'] ?? $this->config->getFrontendUrl() . '/login';
                    if (!empty($loginUrl)) {
                        $ctas[] = ['href' => $loginUrl, 'text' => __('Login to Portal', 'cheapalarms'), 'primary' => false];
                    }
                } elseif (!empty($portalUrl)) {
                    // Fallback: just portal URL
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render estimate email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, portalUrl, resetUrl)
     * @param string|null $variation Override variation (A, B, C, D) or null to auto-detect
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderEstimateEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('estimate', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        if (empty($estimateNumber)) {
            $estimateNumber = __('your estimate', 'cheapalarms');
        }
        $portalUrl = $data['portalUrl'] ?? '';
        $resetUrl = $data['resetUrl'] ?? '';
        
        $isNewUser = $context['isNewUser'] ?? false;
        $hasPasswordSet = $context['hasPasswordSet'] ?? false;
        
        switch ($variation) {
            case 'A': // New User, No Password
                $subject = $estimateNumber 
                    ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                    : __('Your estimate is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('Your estimate %s is ready for review. Click the button below to view your estimate and manage your installation.', 'cheapalarms'),
                    $estimateNumber ? '<strong>#' . esc_html($estimateNumber) . '</strong>' : ''
                ) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View Your Estimate', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // Returning User, Has Password
                $subject = $estimateNumber 
                    ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                    : __('Your estimate is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Great to have you back! Your estimate is ready for review.', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('Your estimate %s is ready. Click the button below to view and manage your installation.', 'cheapalarms'),
                    $estimateNumber ? '<strong>#' . esc_html($estimateNumber) . '</strong>' : ''
                ) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View Your Estimate', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'C': // Returning User, No Password
                $subject = $estimateNumber 
                    ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                    : __('Your estimate is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve prepared a new estimate for you!', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('Your estimate %s is ready. To access it, please set a password for your account.', 'cheapalarms'),
                    $estimateNumber ? '<strong>#' . esc_html($estimateNumber) . '</strong>' : ''
                ) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View Your Estimate', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($resetUrl)) {
                    $ctas[] = ['href' => $resetUrl, 'text' => __('Set Your Password', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'D': // Resend
            default:
                $subject = $estimateNumber 
                    ? sprintf(__('Your estimate #%s is ready', 'cheapalarms'), $estimateNumber)
                    : __('Your estimate is ready', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('As requested, here is your estimate again. Click the button below to view and manage your installation.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('View Your Estimate', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">' . esc_html(__('This invite link remains active for 7 days. If it expires, contact us and we will resend it.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render acceptance confirmation email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, invoiceUrl, portalUrl)
     * @param string|null $variation Override variation (A, B) or null to auto-detect
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderAcceptanceEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('acceptance', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $invoiceUrl = $data['invoiceUrl'] ?? '';
        $portalUrl = $data['portalUrl'] ?? '';
        
        $hasPreviousEstimates = $context['hasPreviousEstimates'] ?? false;
        
        switch ($variation) {
            case 'A': // First Acceptance
                $subject = __('Thank you for accepting your estimate', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . sprintf(
                    __('Thank you for accepting estimate %s! We\'re excited to move forward with your project.', 'cheapalarms'),
                    $estimateNumber ? '<strong>#' . esc_html($estimateNumber) . '</strong>' : ''
                ) . '</p>';
                if (!empty($invoiceUrl)) {
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your invoice has been created and is ready for payment:', 'cheapalarms')) . '</p>';
                } else {
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'re preparing your invoice and will send it to you shortly.', 'cheapalarms')) . '</p>';
                }
                $body .= '</div>';
                $ctas = [];
                if (!empty($invoiceUrl)) {
                    $ctas[] = ['href' => $invoiceUrl, 'text' => __('View & Pay Invoice', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6; margin-top: 20px;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(__('Next Steps:', 'cheapalarms')) . '</p>';
                $body .= '<ul style="margin: 0 0 20px 0; padding-left: 24px;">';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Complete payment using the invoice link above', 'cheapalarms')) . '</li>';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Upload any required photos through your portal', 'cheapalarms')) . '</li>';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Our team will contact you to schedule installation', 'cheapalarms')) . '</li>';
                $body .= '</ul>';
                $body .= '</div>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // Returning Customer
            default:
                $subject = __('Thank you for accepting your estimate', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Thank you for accepting your estimate! We appreciate your continued trust in CheapAlarms.', 'cheapalarms')) . '</p>';
                if (!empty($invoiceUrl)) {
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your invoice has been created and is ready for payment:', 'cheapalarms')) . '</p>';
                } else {
                    $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'re preparing your invoice and will send it to you shortly.', 'cheapalarms')) . '</p>';
                }
                $body .= '</div>';
                $ctas = [];
                if (!empty($invoiceUrl)) {
                    $ctas[] = ['href' => $invoiceUrl, 'text' => __('View & Pay Invoice', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6; margin-top: 20px;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(__('Next Steps:', 'cheapalarms')) . '</p>';
                $body .= '<ul style="margin: 0 0 20px 0; padding-left: 24px;">';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Complete payment using the invoice link above', 'cheapalarms')) . '</li>';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Upload any required photos through your portal', 'cheapalarms')) . '</li>';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Our team will contact you to schedule installation', 'cheapalarms')) . '</li>';
                $body .= '</ul>';
                $body .= '</div>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render invoice ready email with context awareness
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, invoiceNumber, invoiceUrl, invoiceTotal, currency, dueDate, portalUrl)
     * @param string|null $variation Override variation (A, B) or null to auto-detect
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderInvoiceEmail(array $context, array $data, ?string $variation = null): array
    {
        $variation = $variation ?? UserContextHelper::detectEmailVariation('invoice', $context);
        
        $customerName = $data['customerName'] ?? 'Customer';
        $invoiceNumber = $data['invoiceNumber'] ?? '';
        $invoiceUrl = $data['invoiceUrl'] ?? '';
        $invoiceTotal = $data['invoiceTotal'] ?? 0;
        $currency = $data['currency'] ?? 'AUD';
        $dueDate = $data['dueDate'] ?? '';
        $portalUrl = $data['portalUrl'] ?? '';
        
        $hasPreviousEstimates = $context['hasPreviousEstimates'] ?? false;
        
        $formattedTotal = number_format((float)$invoiceTotal, 2);
        $formattedDueDate = '';
        if (!empty($dueDate)) {
            $formattedDueDate = date_i18n(get_option('date_format'), strtotime($dueDate));
        }
        
        switch ($variation) {
            case 'A': // First Invoice
                $subject = __('Your invoice is ready for payment', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Great news! Your invoice is now ready for payment.', 'cheapalarms')) . '</p>';
                $body .= '<div style="background-color: #f5f5f5; padding: 20px; border-radius: 6px; margin: 20px 0;">';
                $body .= '<p style="margin: 0 0 10px 0; font-weight: bold; font-size: 18px;">' . esc_html(sprintf(__('Invoice #%s', 'cheapalarms'), $invoiceNumber)) . '</p>';
                $body .= '<p style="margin: 0 0 10px 0; font-size: 16px;">' . esc_html(sprintf(__('Amount: %s $%s', 'cheapalarms'), $currency, $formattedTotal)) . '</p>';
                if ($formattedDueDate) {
                    $body .= '<p style="margin: 0; font-size: 14px; color: #666666;">' . esc_html(sprintf(__('Due Date: %s', 'cheapalarms'), $formattedDueDate)) . '</p>';
                }
                $body .= '</div>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($invoiceUrl)) {
                    $ctas[] = ['href' => $invoiceUrl, 'text' => __('View & Pay Invoice', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6; margin-top: 20px;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(__('Payment Options:', 'cheapalarms')) . '</p>';
                $body .= '<ul style="margin: 0 0 20px 0; padding-left: 24px;">';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Click the button above to pay online securely', 'cheapalarms')) . '</li>';
                $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Multiple payment methods accepted', 'cheapalarms')) . '</li>';
                $body .= '</ul>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('You can also view this invoice and track your project progress in your portal.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;

            case 'B': // Returning Customer
            default:
                $subject = __('Your invoice is ready for payment', 'cheapalarms');
                $body = $this->getEmailHeader();
                $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
                $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
                $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your invoice is ready for payment.', 'cheapalarms')) . '</p>';
                $body .= '<div style="background-color: #f5f5f5; padding: 20px; border-radius: 6px; margin: 20px 0;">';
                $body .= '<p style="margin: 0 0 10px 0; font-weight: bold; font-size: 18px;">' . esc_html(sprintf(__('Invoice #%s', 'cheapalarms'), $invoiceNumber)) . '</p>';
                $body .= '<p style="margin: 0 0 10px 0; font-size: 16px;">' . esc_html(sprintf(__('Amount: %s $%s', 'cheapalarms'), $currency, $formattedTotal)) . '</p>';
                if ($formattedDueDate) {
                    $body .= '<p style="margin: 0; font-size: 14px; color: #666666;">' . esc_html(sprintf(__('Due Date: %s', 'cheapalarms'), $formattedDueDate)) . '</p>';
                }
                $body .= '</div>';
                $body .= '</div>';
                $ctas = [];
                if (!empty($invoiceUrl)) {
                    $ctas[] = ['href' => $invoiceUrl, 'text' => __('View & Pay Invoice', 'cheapalarms'), 'primary' => true];
                }
                if (!empty($portalUrl)) {
                    $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => false];
                }
                if (!empty($ctas)) {
                    $body .= $this->getCTAs($ctas);
                }
                $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6; margin-top: 20px;">';
                $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('You can view this invoice and track your project progress in your portal.', 'cheapalarms')) . '</p>';
                $body .= '</div>';
                $body .= '</div>';
                $body .= $this->getEmailFooter();
                break;
        }

        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $variation,
        ];
    }

    /**
     * Render booking confirmation email
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, scheduledDate, scheduledTime, notes, invoiceUrl, portalUrl)
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderBookingEmail(array $context, array $data): array
    {
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $scheduledDate = $data['scheduledDate'] ?? '';
        $scheduledTime = $data['scheduledTime'] ?? '';
        $notes = $data['notes'] ?? '';
        $invoiceUrl = $data['invoiceUrl'] ?? '';
        $portalUrl = $data['portalUrl'] ?? '';
        
        // Format date
        $formattedDate = '';
        if ($scheduledDate) {
            try {
                $dateObj = new \DateTime($scheduledDate);
                $formattedDate = $dateObj->format('l, F j, Y'); // e.g., "Monday, December 3, 2024"
            } catch (\Exception $e) {
                $formattedDate = $scheduledDate;
            }
        }
        
        // Format time
        $formattedTime = '';
        if ($scheduledTime) {
            try {
                $timeObj = \DateTime::createFromFormat('H:i', $scheduledTime);
                if ($timeObj) {
                    $formattedTime = $timeObj->format('g:i A'); // e.g., "2:30 PM"
                } else {
                    $formattedTime = $scheduledTime;
                }
            } catch (\Exception $e) {
                $formattedTime = $scheduledTime;
            }
        }
        
        $subject = __('Your installation has been scheduled', 'cheapalarms');
        $body = $this->getEmailHeader();
        $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
        $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
        $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
        $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Great news! Your installation has been scheduled.', 'cheapalarms')) . '</p>';
        
        $body .= '<div style="background-color: #f0f9ff; border-left: 4px solid #c95375; padding: 16px; margin: 20px 0; border-radius: 6px;">';
        $body .= '<p style="margin: 0 0 8px 0; font-weight: bold; font-size: 16px;">' . esc_html(__('Installation Details:', 'cheapalarms')) . '</p>';
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
        
        $body .= '</div>';
        $ctas = [];
        if (!empty($invoiceUrl)) {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Next step: Complete your payment to finalize everything.', 'cheapalarms')) . '</p>';
            $ctas[] = ['href' => $invoiceUrl, 'text' => __('Complete Payment', 'cheapalarms'), 'primary' => true];
        } else {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('You can complete your payment and view all details in your portal:', 'cheapalarms')) . '</p>';
        }
        if (!empty($portalUrl)) {
            $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => empty($invoiceUrl)];
        }
        if (!empty($ctas)) {
            $body .= $this->getCTAs($ctas);
        }
        $body .= '<p style="margin: 20px 0 0 0; line-height: 1.6;">' . esc_html(__('If you need to reschedule or have any questions, please contact us.', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        $body .= $this->getEmailFooter();
        
        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => 'standard',
        ];
    }

    /**
     * Render payment confirmation email
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, paymentAmount, currency, transactionId, paidAt, bookingDate, portalUrl)
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderPaymentEmail(array $context, array $data): array
    {
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $paymentAmount = $data['paymentAmount'] ?? 0;
        $currency = $data['currency'] ?? 'AUD';
        $transactionId = $data['transactionId'] ?? '';
        $paidAt = $data['paidAt'] ?? current_time('mysql');
        $bookingDate = $data['bookingDate'] ?? '';
        $portalUrl = $data['portalUrl'] ?? '';
        
        $formattedAmount = number_format((float)$paymentAmount, 2);
        
        // Format payment date
        $formattedDate = '';
        if ($paidAt) {
            try {
                $dateObj = new \DateTime($paidAt);
                $formattedDate = $dateObj->format('l, F j, Y \a\t g:i A'); // e.g., "Monday, December 3, 2024 at 2:30 PM"
            } catch (\Exception $e) {
                $formattedDate = $paidAt;
            }
        }
        
        // Format booking date
        $formattedBookingDate = '';
        if ($bookingDate) {
            try {
                $dateObj = new \DateTime($bookingDate);
                $formattedBookingDate = $dateObj->format('l, F j, Y');
            } catch (\Exception $e) {
                $formattedBookingDate = $bookingDate;
            }
        }
        
        $subject = __('Payment confirmed - Thank you!', 'cheapalarms');
        $body = $this->getEmailHeader();
        $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
        $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
        $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
        $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your payment has been successfully processed!', 'cheapalarms')) . '</p>';
        
        $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0; border-radius: 6px;">';
        $body .= '<p style="margin: 0 0 8px 0; font-weight: bold; font-size: 16px;">' . esc_html(__('Payment Details:', 'cheapalarms')) . '</p>';
        $body .= '<p style="margin: 4px 0;">💰 <strong>' . esc_html(__('Amount:', 'cheapalarms')) . '</strong> ' . esc_html($currency . ' $' . $formattedAmount) . '</p>';
        if ($transactionId) {
            $body .= '<p style="margin: 4px 0;">📄 <strong>' . esc_html(__('Transaction ID:', 'cheapalarms')) . '</strong> ' . esc_html($transactionId) . '</p>';
        }
        if ($formattedDate) {
            $body .= '<p style="margin: 4px 0;">✅ <strong>' . esc_html(__('Paid on:', 'cheapalarms')) . '</strong> ' . esc_html($formattedDate) . '</p>';
        }
        $body .= '</div>';
        
        if ($formattedBookingDate) {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(sprintf(
                __('Your installation is confirmed for %s.', 'cheapalarms'),
                $formattedBookingDate
            )) . '</p>';
        } else {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('Your installation is confirmed.', 'cheapalarms')) . '</p>';
        }
        
        $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ll be in touch soon with installation details and any final preparations needed.', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        
        $ctas = [];
        if (!empty($portalUrl)) {
            $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
        }
        if (!empty($ctas)) {
            $body .= $this->getCTAs($ctas);
        }
        
        $body .= '<p style="margin: 20px 0 0 0; line-height: 1.6;">' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        $body .= $this->getEmailFooter();
        
        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => 'standard',
        ];
    }

    /**
     * Render changes requested email
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, adminNote, photosRequired, portalUrl)
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderChangesRequestedEmail(array $context, array $data): array
    {
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $adminNote = $data['adminNote'] ?? '';
        $photosRequired = $data['photosRequired'] ?? false;
        $portalUrl = $data['portalUrl'] ?? '';
        
        $hasNote = !empty($adminNote);
        
        $subject = $estimateNumber 
            ? sprintf(__('Update needed for Estimate #%s', 'cheapalarms'), $estimateNumber)
            : __('Update needed for your estimate', 'cheapalarms');
        
        $body = $this->getEmailHeader();
        $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
        $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
        $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
        $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve reviewed your estimate and need a few updates before we can proceed.', 'cheapalarms')) . '</p>';
        
        if ($photosRequired) {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We need some additional or updated photos of your installation area.', 'cheapalarms')) . '</p>';
        } else {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We need some additional information to finalize your estimate.', 'cheapalarms')) . '</p>';
        }
        
        // Include admin's note if provided
        if ($hasNote) {
            $body .= '<div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin: 20px 0; border-radius: 6px;">';
            $body .= '<p style="margin: 0 0 8px 0; font-weight: bold; color: #92400e;">' . esc_html(__('Note from our team:', 'cheapalarms')) . '</p>';
            $body .= '<p style="margin: 0; color: #78350f;">' . nl2br(esc_html($adminNote)) . '</p>';
            $body .= '</div>';
        }
        
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(__('What you need to do:', 'cheapalarms')) . '</p>';
        $body .= '<ul style="margin: 0 0 20px 0; padding-left: 24px;">';
        if ($photosRequired) {
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Review the note above for specific photo requirements', 'cheapalarms')) . '</li>';
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Upload the additional or updated photos in your portal', 'cheapalarms')) . '</li>';
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Submit your photos for review again', 'cheapalarms')) . '</li>';
        } else {
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Review the note above for specific requirements', 'cheapalarms')) . '</li>';
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Update your information in the portal', 'cheapalarms')) . '</li>';
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Request a review again when ready', 'cheapalarms')) . '</li>';
        }
        $body .= '</ul>';
        $body .= '</div>';
        
        $ctas = [];
        if (!empty($portalUrl)) {
            $ctas[] = ['href' => $portalUrl, 'text' => __('Open Your Portal', 'cheapalarms'), 'primary' => true];
        }
        if (!empty($ctas)) {
            $body .= $this->getCTAs($ctas);
        }
        
        $body .= '<p style="margin: 20px 0 0 0; line-height: 1.6;">' . esc_html(__('If you have any questions or need clarification, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        $body .= $this->getEmailFooter();
        
        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => 'standard',
        ];
    }

    /**
     * Render review completion email (with conditional logic for revisions)
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, hasRevision, revision, portalUrl)
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderReviewCompletionEmail(array $context, array $data): array
    {
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $hasRevision = $data['hasRevision'] ?? false;
        $revision = $data['revision'] ?? null;
        $portalUrl = $data['portalUrl'] ?? '';
        
        $subject = $hasRevision
            ? __('Your estimate has been reviewed and updated', 'cheapalarms')
            : __('Your estimate review is complete', 'cheapalarms');
        
        $body = $this->getEmailHeader();
        $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
        $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
        $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
        
        if ($hasRevision && $revision) {
            // If revision exists, mention the update
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve completed reviewing your installation photos and updated your estimate accordingly.', 'cheapalarms')) . '</p>';
            
            // Show revision summary if available
            $netChange = floatval($revision['netChange'] ?? 0);
            $isSavings = $netChange < 0;
            
            if ($isSavings) {
                $body .= '<div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 16px; margin: 20px 0; border-radius: 6px;">';
                $body .= '<p style="margin: 0; font-size: 18px; font-weight: bold; color: #10b981;">' . esc_html(__('🎉 Great News!', 'cheapalarms')) . '</p>';
                $body .= '<p style="margin: 8px 0 0 0;">' . esc_html(sprintf(
                    __('You save %s!', 'cheapalarms'),
                    '$' . number_format(abs($netChange), 2)
                )) . '</p>';
                $body .= '</div>';
            } else if ($netChange > 0) {
                $body .= '<div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; margin: 20px 0; border-radius: 6px;">';
                $body .= '<p style="margin: 0;">' . esc_html(sprintf(
                    __('Your estimate has been updated. Additional amount: %s', 'cheapalarms'),
                    '$' . number_format($netChange, 2)
                )) . '</p>';
                $body .= '</div>';
            }
        } else {
            // No changes made
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve completed reviewing your installation photos. Your estimate is ready for acceptance!', 'cheapalarms')) . '</p>';
        }
        
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(__('Next steps:', 'cheapalarms')) . '</p>';
        $body .= '<ul style="margin: 0 0 20px 0; padding-left: 24px;">';
        $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Review the updated estimate details', 'cheapalarms')) . '</li>';
        $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Accept the estimate when ready', 'cheapalarms')) . '</li>';
        $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Schedule your installation', 'cheapalarms')) . '</li>';
        $body .= '</ul>';
        $body .= '</div>';
        
        $ctas = [];
        if (!empty($portalUrl)) {
            $ctas[] = ['href' => $portalUrl, 'text' => __('View Updated Estimate', 'cheapalarms'), 'primary' => true];
        }
        if (!empty($ctas)) {
            $body .= $this->getCTAs($ctas);
        }
        
        $body .= '<p style="margin: 20px 0 0 0; line-height: 1.6;">' . esc_html(__('If you have any questions, please don\'t hesitate to contact us.', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        $body .= $this->getEmailFooter();
        
        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $hasRevision ? 'with-revision' : 'standard',
        ];
    }

    /**
     * Render revision notification email (complex data-driven)
     * 
     * @param array $context User context from UserContextHelper
     * @param array $data Email data (customerName, estimateNumber, revisionData, portalUrl, currency)
     * @return array ['subject' => string, 'body' => string, 'variation' => string]
     */
    public function renderRevisionEmail(array $context, array $data): array
    {
        $customerName = $data['customerName'] ?? 'Customer';
        $estimateNumber = $data['estimateNumber'] ?? '';
        $revisionData = $data['revisionData'] ?? [];
        $portalUrl = $data['portalUrl'] ?? '';
        $currency = $data['currency'] ?? 'AUD';
        
        // Validate and sanitize numeric values
        $oldTotal = floatval($revisionData['oldTotal'] ?? 0);
        $newTotal = floatval($revisionData['newTotal'] ?? 0);
        $netChange = floatval($revisionData['netChange'] ?? 0);
        
        // Ensure values are finite
        if (!is_finite($oldTotal)) $oldTotal = 0.0;
        if (!is_finite($newTotal)) $newTotal = 0.0;
        if (!is_finite($netChange)) $netChange = 0.0;
        
        $adminNote = sanitize_text_field($revisionData['adminNote'] ?? '');
        $isSavings = $netChange < 0;
        $isIncrease = $netChange > 0;
        
        // Subject line
        $subject = $isSavings 
            ? sprintf(__('🎉 Great news! Your CheapAlarms estimate has been updated - Save %s %s', 'cheapalarms'), $currency, number_format(abs($netChange), 2))
            : __('Your CheapAlarms estimate has been updated', 'cheapalarms');
        
        $body = $this->getEmailHeader();
        $body .= '<div style="padding: 30px 20px; background-color: #ffffff;">';
        $body .= '<h2 style="font-size: 20px; font-weight: bold; color: #333333; margin: 0 0 20px 0; line-height: 1.4;">' . esc_html($subject) . '</h2>';
        $body .= '<div style="color: #333333; font-size: 16px; line-height: 1.6;">';
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;">' . esc_html(sprintf(__('Hi %s,', 'cheapalarms'), $customerName)) . '</p>';
        
        if ($isSavings) {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;"><strong style="color: #10b981; font-size: 18px;">' . esc_html(__('Good news!', 'cheapalarms')) . '</strong> ' . esc_html(__('We\'ve reviewed the installation photos you submitted and found opportunities to optimize your installation.', 'cheapalarms')) . '</p>';
        } else {
            $body .= '<p style="margin: 0 0 15px 0; line-height: 1.6;">' . esc_html(__('We\'ve carefully reviewed the installation photos you submitted and updated your estimate to ensure accurate pricing for your specific site.', 'cheapalarms')) . '</p>';
        }
        
        // Pricing box
        $boxColor = $isSavings ? '#10b981' : '#1EA6DF';
        $body .= '<div style="background: linear-gradient(135deg, ' . esc_attr($boxColor) . ', ' . esc_attr($isSavings ? '#059669' : '#0e7490') . '); color: white; padding: 24px; border-radius: 16px; margin: 24px 0; text-align: center;">';
        $body .= '<div style="font-size: 14px; opacity: 0.9; margin-bottom: 8px;">' . esc_html(__('YOUR UPDATED PRICING', 'cheapalarms')) . '</div>';
        $body .= '<div style="font-size: 24px; text-decoration: line-through; opacity: 0.7; margin-bottom: 8px;">' . esc_html($currency . ' ' . number_format($oldTotal, 2)) . '</div>';
        $body .= '<div style="font-size: 36px; font-weight: bold; margin-bottom: 16px;">' . esc_html($currency . ' ' . number_format($newTotal, 2)) . '</div>';
        
        if ($netChange !== 0) {
            if ($isSavings) {
                $body .= '<div style="font-size: 28px; font-weight: bold; background: rgba(255,255,255,0.2); padding: 12px 24px; border-radius: 12px; display: inline-block;">🎊 ' . esc_html(__('YOU SAVE', 'cheapalarms') . ' ' . $currency . ' ' . number_format(abs($netChange), 2)) . '</div>';
            } else {
                $body .= '<div style="font-size: 18px; background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; display: inline-block;">' . esc_html(__('Additional:', 'cheapalarms') . ' +' . $currency . ' ' . number_format(abs($netChange), 2)) . '</div>';
            }
        }
        $body .= '</div>';
        
        // Admin note
        if ($adminNote) {
            $body .= '<div style="background: #f8f9fa; border-left: 4px solid ' . esc_attr($boxColor) . '; padding: 16px; border-radius: 8px; margin: 24px 0;">';
            $body .= '<div style="font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 8px;">' . esc_html(__('FROM YOUR INSTALLER', 'cheapalarms')) . '</div>';
            $body .= '<div style="color: #1f2937;">' . nl2br(esc_html($adminNote)) . '</div>';
            $body .= '</div>';
        }
        
        // Call to action
        $body .= '<p style="margin: 0 0 15px 0; font-weight: 500;"><strong>' . esc_html(__('What\'s next:', 'cheapalarms')) . '</strong></p>';
        $body .= '<ol style="margin: 0 0 20px 0; padding-left: 24px;">';
        $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('Review the updated estimate in your portal', 'cheapalarms')) . '</li>';
        if ($isSavings) {
            $body .= '<li style="margin: 0 0 8px 0;"><strong>' . esc_html(__('Accept now to lock in your savings!', 'cheapalarms')) . '</strong></li>';
        } else {
            $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('If you\'re happy with the pricing, accept the estimate', 'cheapalarms')) . '</li>';
        }
        $body .= '<li style="margin: 0 0 8px 0;">' . esc_html(__('We\'ll then create your invoice and schedule installation', 'cheapalarms')) . '</li>';
        $body .= '</ol>';
        $body .= '</div>';
        
        $ctas = [];
        if (!empty($portalUrl)) {
            $ctas[] = ['href' => $portalUrl, 'text' => __('View Updated Estimate', 'cheapalarms'), 'primary' => true];
        }
        if (!empty($ctas)) {
            $body .= $this->getCTAs($ctas);
        }
        
        $body .= '<p style="margin: 20px 0 0 0; color: #6b7280; font-size: 14px;">' . esc_html(__('Have questions about the changes? Just reply to this email!', 'cheapalarms')) . '</p>';
        $body .= '</div>';
        $body .= $this->getEmailFooter();
        
        return [
            'subject' => $subject,
            'body' => $body,
            'variation' => $isSavings ? 'savings' : ($isIncrease ? 'increase' : 'standard'),
        ];
    }

    /**
     * Get email header HTML
     */
    private function getEmailHeader(): string
    {
        return '<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color: #ffffff; padding: 20px; text-align: center; border-bottom: 2px solid #c95375;">
                <h1 style="color: #c95375; font-size: 24px; font-weight: bold; margin: 0; font-family: Arial, sans-serif;">CheapAlarms</h1>
                <p style="color: #666666; font-size: 12px; margin: 5px 0 0 0; font-family: Arial, sans-serif;">' . esc_html(__('Your Security Partner', 'cheapalarms')) . '</p>
            </div>';
    }

    /**
     * Get email footer HTML
     */
    private function getEmailFooter(): string
    {
        return '<div style="background-color: #f5f5f5; padding: 30px 20px; text-align: center; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666666; font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto;">
                <p style="margin: 0 0 10px 0;"><strong style="color: #333333;">CheapAlarms</strong></p>
                <p style="margin: 0 0 10px 0;">' . esc_html(__('Your trusted security partner', 'cheapalarms')) . '</p>
                <p style="margin: 0; font-size: 11px; color: #999999;">' . esc_html(__('This email was sent to you regarding your account. If you have any questions, please contact our support team.', 'cheapalarms')) . '</p>
            </div>
        </div>
    </div>';
    }

    /**
     * Get CTA buttons HTML
     * 
     * @param array $ctas Array of ['href' => string, 'text' => string, 'primary' => bool]
     */
    private function getCTAs(array $ctas): string
    {
        if (empty($ctas)) {
            return '';
        }

        $html = '<div style="text-align: center; margin: 30px 0;">';
        $visibleIndex = 0;
        
        foreach ($ctas as $cta) {
            // Skip if href is empty
            if (empty($cta['href'])) {
                continue;
            }

            // Wrap secondary CTAs in a div (first visible is index 0, second is index 1, etc.)
            if ($visibleIndex > 0) {
                $html .= '<div style="margin-top: 15px;">';
            }
            
            if ($cta['primary'] ?? false) {
                $html .= '<a href="' . esc_url($cta['href']) . '" style="display: inline-block; padding: 12px 24px; background-color: #c95375; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px; text-align: center; font-family: Arial, sans-serif;">' . esc_html($cta['text'] ?? '') . '</a>';
            } else {
                $html .= '<a href="' . esc_url($cta['href']) . '" style="color: #1EA6DF; text-decoration: underline; font-size: 14px;">' . esc_html($cta['text'] ?? '') . '</a>';
            }
            
            // Close div for secondary CTAs
            if ($visibleIndex > 0) {
                $html .= '</div>';
            }
            
            $visibleIndex++;
        }
        
        $html .= '</div>';
        return $html;
    }
}

