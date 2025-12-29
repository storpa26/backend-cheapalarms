<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\Logger;
use WP_Error;

use function is_wp_error;
use function wp_json_encode;

class EstimateSnapshotSyncService
{
    public function __construct(
        private EstimateService $estimateService,
        private EstimateSnapshotRepository $repo,
        private Logger $logger
    ) {
    }

    /**
     * Sync ALL estimates for a location into snapshots table.
     *
     * @return array{ok:bool, locationId:string, pages:int, count:int, durationMs:float}|WP_Error
     */
    public function syncLocation(string $locationId, int $pageSize = 50, int $maxPages = 200)
    {
        $pageSize = max(1, min(100, $pageSize));
        $offset   = '0';
        $pages    = 0;
        $count    = 0;
        $start    = microtime(true);

        while ($pages < $maxPages) {
            $pages++;

            $page = $this->estimateService->fetchEstimateListPage($locationId, $pageSize, $offset);
            if (is_wp_error($page)) {
                return $page;
            }

            $items = $page['items'] ?? [];

            $normalized = [];
            foreach ($items as $record) {
                $estimateId = $record['estimateId'] ?? $record['id'] ?? $record['_id'] ?? null;
                if (!$estimateId) {
                    continue;
                }

                $email =
                    $record['contact']['email'] ??
                    $record['contactDetails']['email'] ??
                    ($record['sentTo']['email'][0] ?? '') ??
                    '';

                $normalized[] = [
                    'id'             => (string)$estimateId,
                    'estimateNumber' => $record['estimateNumber'] ?? null,
                    'email'          => $email,
                    'status'         => $record['estimateStatus'] ?? $record['status'] ?? '',
                    'total'          => (float)($record['total'] ?? 0),
                    'currency'       => $record['currency'] ?? 'AUD',
                    'createdAt'      => $record['createdAt'] ?? null,
                    'updatedAt'      => $record['updatedAt'] ?? null,
                    'rawJson'        => wp_json_encode($record),
                ];
            }

            $res = $this->repo->upsertMany($locationId, $normalized);
            if (is_wp_error($res)) {
                return $res;
            }

            $count += count($normalized);

            $next = $page['nextOffset'] ?? null;
            if (!$next) {
                break;
            }
            $offset = (string)$next;
        }

        $durationMs = round((microtime(true) - $start) * 1000, 2);

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->debug('[ADMIN_SNAPSHOTS] synced location', [
                'locationId' => $locationId,
                'pages'      => $pages,
                'count'      => $count,
                'durationMs' => $durationMs,
            ]);
        }

        return [
            'ok'         => true,
            'locationId' => $locationId,
            'pages'      => $pages,
            'count'      => $count,
            'durationMs' => $durationMs,
        ];
    }
}


