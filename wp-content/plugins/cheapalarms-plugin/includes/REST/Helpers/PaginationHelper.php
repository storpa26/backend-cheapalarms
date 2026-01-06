<?php

namespace CheapAlarms\Plugin\REST\Helpers;

use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Pagination Helper
 * 
 * Standardizes pagination format across all list endpoints
 */
class PaginationHelper
{
    private const DEFAULT_LIMIT = 20;
    private const MAX_LIMIT = 100;

    /**
     * Parse pagination parameters from request
     * 
     * @param WP_REST_Request $request
     * @return array{page: int, limit: int, offset: int}
     */
    public static function parseRequest(WP_REST_Request $request): array
    {
        $page = max(1, (int) ($request->get_param('page') ?? 1));
        $limit = max(1, min(self::MAX_LIMIT, (int) ($request->get_param('limit') ?? $request->get_param('per_page') ?? self::DEFAULT_LIMIT)));
        $offset = ($page - 1) * $limit;

        return [
            'page' => $page,
            'limit' => $limit,
            'offset' => $offset,
        ];
    }

    /**
     * Format paginated response
     * 
     * @param array<mixed> $items
     * @param int $total
     * @param int $page
     * @param int $limit
     * @param WP_REST_Request|null $request
     * @return WP_REST_Response
     */
    public static function formatResponse(
        array $items,
        int $total,
        int $page,
        int $limit,
        ?WP_REST_Request $request = null
    ): WP_REST_Response {
        $totalPages = max(1, (int) ceil($total / $limit));

        $response = new WP_REST_Response([
            'items' => $items,
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'totalPages' => $totalPages,
            ],
        ], 200);

        // Add pagination headers (WordPress REST API standard)
        $response->header('X-WP-Total', (string) $total);
        $response->header('X-WP-TotalPages', (string) $totalPages);
        $response->header('X-Page', (string) $page);
        $response->header('X-Per-Page', (string) $limit);

        // Add Link headers for navigation (RFC 5988 format - single header with comma-separated links)
        if ($request) {
            $baseUrl = rest_url($request->get_route());
            $queryParams = $request->get_query_params();
            
            // Remove page from query params for base URL
            unset($queryParams['page']);
            if (!empty($queryParams)) {
                $baseUrl = add_query_arg($queryParams, $baseUrl);
            }

            // Build all links and combine into single Link header (RFC 5988)
            $links = [];
            
            // First page link (always include)
            $firstUrl = add_query_arg('page', 1, $baseUrl);
            $links[] = '<' . esc_url($firstUrl) . '>; rel="first"';
            
            // Previous page link
            if ($page > 1) {
                $prevUrl = add_query_arg('page', $page - 1, $baseUrl);
                $links[] = '<' . esc_url($prevUrl) . '>; rel="prev"';
            }
            
            // Next page link
            if ($page < $totalPages) {
                $nextUrl = add_query_arg('page', $page + 1, $baseUrl);
                $links[] = '<' . esc_url($nextUrl) . '>; rel="next"';
            }
            
            // Last page link (always include)
            $lastUrl = add_query_arg('page', $totalPages, $baseUrl);
            $links[] = '<' . esc_url($lastUrl) . '>; rel="last"';
            
            // Combine all links into single Link header (RFC 5988)
            if (!empty($links)) {
                $response->header('Link', implode(', ', $links));
            }
        }

        return $response;
    }

    /**
     * Calculate total pages
     * 
     * @param int $total
     * @param int $limit
     * @return int
     */
    public static function calculateTotalPages(int $total, int $limit): int
    {
        return max(1, (int) ceil($total / $limit));
    }

    /**
     * Validate pagination parameters
     * 
     * @param int $page
     * @param int $limit
     * @return array{page: int, limit: int}|WP_Error
     */
    public static function validate(int $page, int $limit)
    {
        if ($page < 1) {
            return new \WP_Error(
                'invalid_page',
                __('Page must be greater than 0.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        if ($limit < 1) {
            return new \WP_Error(
                'invalid_limit',
                __('Limit must be greater than 0.', 'cheapalarms'),
                ['status' => 400]
            );
        }

        if ($limit > self::MAX_LIMIT) {
            return new \WP_Error(
                'limit_too_high',
                sprintf(__('Limit cannot exceed %d.', 'cheapalarms'), self::MAX_LIMIT),
                ['status' => 400]
            );
        }

        return [
            'page' => $page,
            'limit' => $limit,
        ];
    }
}

