<?php

namespace CheapAlarms\Plugin\Services;

/**
 * Helper class for detecting user context for email personalization
 */
class UserContextHelper
{
    /**
     * Get user context for email personalization
     * 
     * @param int|null $userId User ID (null if user doesn't exist yet)
     * @param string $email User email address
     * @param string|null $currentEstimateId Current estimate ID (optional)
     * @return array Context array with: isNewUser, hasPasswordSet, hasPreviousEstimates, estimateCount, previousEstimateNumbers
     */
    public static function getUserContext(?int $userId, string $email, ?string $currentEstimateId = null): array
    {
        // Validate inputs
        $email = sanitize_email($email);
        if (empty($email)) {
            // Invalid email, treat as new user
            return [
                'isNewUser' => true,
                'hasPasswordSet' => false,
                'hasPreviousEstimates' => false,
                'estimateCount' => 0,
                'totalEstimateCount' => 1,
                'previousEstimateNumbers' => [],
                'lastLoginAt' => null,
                'userRegistered' => null,
            ];
        }

        // If no user ID, check if user exists by email
        if (!$userId || $userId <= 0) {
            $foundUserId = email_exists($email);
            $userId = ($foundUserId !== false && $foundUserId > 0) ? (int) $foundUserId : null;
        }

        // Ensure userId is valid integer
        $userId = ($userId && $userId !== false && $userId > 0) ? (int) $userId : null;
        
        // Get estimate IDs for this user (fetch once, reuse for efficiency)
        $allEstimateIds = [];
        if ($userId) {
            $allEstimateIds = get_user_meta($userId, 'ca_estimate_ids', true);
            if (!is_array($allEstimateIds)) {
                $allEstimateIds = [];
            }
        }
        
        // Remove current estimate from count if provided (to check for previous estimates)
        $estimateIds = $allEstimateIds;
        if ($currentEstimateId && in_array($currentEstimateId, $estimateIds, true)) {
            $estimateIds = array_values(array_filter($estimateIds, fn($id) => $id !== $currentEstimateId));
        }

        // Check password status
        $hasPasswordSet = false;
        if ($userId) {
            // Check if password was explicitly set (not just account created)
            $passwordSetAt = get_user_meta($userId, 'ca_password_set_at', true);
            $lastLogin = get_user_meta($userId, 'ca_last_login', true);
            
            // User has password set if:
            // 1. They've explicitly set it (ca_password_set_at exists)
            // 2. They've logged in before (ca_last_login exists)
            if ($passwordSetAt || $lastLogin) {
                $hasPasswordSet = true;
            } else {
                // 3. Account was created but user_registered is old (more than 24 hours ago) - likely set password
                // This handles accounts created before tracking was implemented
                $user = get_user_by('id', $userId);
                if ($user && isset($user->user_registered) && $user->user_registered) {
                    $registeredTime = strtotime($user->user_registered);
                    $now = current_time('timestamp');
                    // If account is older than 24 hours and no password tracking, assume password might be set
                    // But be conservative - only if account is very old (24+ hours)
                    if ($registeredTime !== false && ($now - $registeredTime) > DAY_IN_SECONDS) {
                        // Account is old, likely has password set
                        $hasPasswordSet = true;
                    }
                }
            }
        }

        $previousEstimateCount = count($estimateIds);
        $hasPreviousEstimates = $previousEstimateCount > 0;
        
        // Calculate total estimate count (previous + current if provided)
        $totalEstimateCount = $previousEstimateCount;
        if ($currentEstimateId && $userId) {
            // Check if current estimate is already in the full list
            if (is_array($allEstimateIds) && in_array($currentEstimateId, $allEstimateIds, true)) {
                // Current estimate is in the list, so total is the count of all estimates
                $totalEstimateCount = count($allEstimateIds);
            } else {
                // Current estimate is new, add 1 to previous count
                $totalEstimateCount = $previousEstimateCount + 1;
            }
            // Defensive check: ensure totalEstimateCount is at least 1 when currentEstimateId is provided
            $totalEstimateCount = max(1, $totalEstimateCount);
        } elseif ($currentEstimateId) {
            // New user with current estimate (edge case)
            $totalEstimateCount = 1;
        } elseif ($userId) {
            // No current estimate provided, use count of all estimates
            if (is_array($allEstimateIds) && !empty($allEstimateIds)) {
                $totalEstimateCount = count($allEstimateIds);
            } else {
                // Fallback: use previousEstimateCount (which is the full count when no currentEstimateId)
                $totalEstimateCount = $previousEstimateCount;
            }
        }
        
        // Determine if user is "effectively new" for email purposes
        // A user is effectively new if:
        // 1. They don't exist (userId is null), OR
        // 2. They exist but have no password set AND no previous estimates
        //    (This handles the case where user was just created for this quote request)
        $isNewUser = !$userId;
        if ($userId && !$hasPasswordSet && $previousEstimateCount === 0) {
            // User exists but was likely just created - treat as new user for email personalization
            $isNewUser = true;
        }

        // Get previous estimate numbers (if available)
        $previousEstimateNumbers = [];
        // Note: We'd need to fetch these from GHL or portal meta, but for now just return count
        // This can be enhanced later if needed

        return [
            'isNewUser' => $isNewUser,
            'hasPasswordSet' => $hasPasswordSet,
            'hasPreviousEstimates' => $hasPreviousEstimates,
            'estimateCount' => $previousEstimateCount, // Count of previous estimates (for variation detection)
            'totalEstimateCount' => $totalEstimateCount, // Total count including current (for email display)
            'previousEstimateNumbers' => $previousEstimateNumbers,
            'lastLoginAt' => $userId ? get_user_meta($userId, 'ca_last_login', true) : null,
            'userRegistered' => $userId ? (($userData = get_userdata($userId)) ? ($userData->user_registered ?? null) : null) : null,
        ];
    }

    /**
     * Detect which email variation to use based on context
     * 
     * @param string $emailType Email type (quote-request, password-reset, etc.)
     * @param array $context User context from getUserContext()
     * @return string Variation letter (A, B, C, D, E)
     */
    public static function detectEmailVariation(string $emailType, array $context): string
    {
        $isNewUser = $context['isNewUser'] ?? false;
        $hasPasswordSet = $context['hasPasswordSet'] ?? false;
        $hasPreviousEstimates = $context['hasPreviousEstimates'] ?? false;
        $estimateCount = $context['estimateCount'] ?? 0;

        switch ($emailType) {
            case 'quote-request':
                // Check for multiple estimates first (highest priority) - 2+ previous estimates
                if ($hasPreviousEstimates && $estimateCount > 1) return 'D';
                // Then check new vs returning
                if ($isNewUser && !$hasPasswordSet) return 'A';
                if (!$isNewUser && $hasPasswordSet) return 'B';
                if (!$isNewUser && !$hasPasswordSet) return 'C';
                return 'A';

            case 'password-reset':
                if ($isNewUser && !$hasPasswordSet) return 'A';
                if (!$isNewUser && !$hasPasswordSet) return 'B';
                if (!$isNewUser && $hasPasswordSet) return 'B'; // Forgot password
                return 'A';

            case 'portal-invite':
                // Check for multiple estimates first (highest priority)
                if ($hasPreviousEstimates && $estimateCount > 1) return 'E';
                // Then check other conditions
                if ($isNewUser && !$hasPasswordSet) return 'A';
                if ($isNewUser && $hasPasswordSet) return 'B';
                if (!$isNewUser && $hasPasswordSet) return 'C';
                if (!$isNewUser && !$hasPasswordSet) return 'D';
                return 'A';

            case 'estimate':
                if ($isNewUser && !$hasPasswordSet) return 'A';
                if (!$isNewUser && $hasPasswordSet) return 'B';
                if (!$isNewUser && !$hasPasswordSet) return 'C';
                return 'D'; // Resend

            case 'acceptance':
                // First acceptance vs returning customer
                if ($isNewUser || !$hasPreviousEstimates) return 'A';
                return 'B'; // Returning customer

            case 'invoice':
                // First invoice vs returning customer
                if ($isNewUser || !$hasPreviousEstimates) return 'A';
                return 'B'; // Returning customer

            default:
                return 'A';
        }
    }
}

