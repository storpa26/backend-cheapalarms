<?php

namespace CheapAlarms\Plugin\Commands;

use WP_CLI;
use WP_CLI_Command;
use CheapAlarms\Plugin\Services\PortalService;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Config\Config;

/**
 * WP-CLI command to repair payment records and recalculate totals
 * 
 * Usage:
 *   wp cheapalarms repair-payments <estimate-id> [--dry-run]
 *   wp cheapalarms repair-payments all [--dry-run]
 */
class RepairPaymentsCommand extends WP_CLI_Command
{
    private PortalService $portalService;
    private Container $container;
    private Config $config;

    public function __construct()
    {
        $this->container = new Container();
        $this->config = $this->container->get(Config::class);
        $this->portalService = $this->container->get(PortalService::class);
    }

    /**
     * Repair payment records for an estimate
     * 
     * ## OPTIONS
     * 
     * <estimate-id>
     * : Estimate ID to repair, or 'all' to repair all estimates
     * 
     * [--dry-run]
     * : Run in dry-run mode (don't save changes)
     * 
     * ## EXAMPLES
     * 
     *     # Repair a specific estimate
     *     wp cheapalarms repair-payments abc123
     * 
     *     # Dry-run to see what would be changed
     *     wp cheapalarms repair-payments abc123 --dry-run
     * 
     *     # Repair all estimates
     *     wp cheapalarms repair-payments all
     * 
     * @param array $args Positional arguments
     * @param array $assoc_args Associative arguments
     */
    public function repair_payments($args, $assoc_args)
    {
        $estimateId = $args[0] ?? null;
        $dryRun = isset($assoc_args['dry-run']);

        if (empty($estimateId)) {
            WP_CLI::error('Estimate ID is required. Use "all" to repair all estimates.');
        }

        if ($estimateId === 'all') {
            $this->repairAllEstimates($dryRun);
        } else {
            $this->repairEstimate($estimateId, $dryRun);
        }
    }

    /**
     * Repair a single estimate
     */
    private function repairEstimate(string $estimateId, bool $dryRun): void
    {
        WP_CLI::log("Repairing payments for estimate: {$estimateId}");

        // Get meta directly (using same method as PortalService)
        $metaJson = get_option('ca_portal_meta_' . $estimateId, null);
        if (empty($metaJson)) {
            WP_CLI::warning("Estimate {$estimateId} not found or has no meta data.");
            return;
        }
        
        $meta = json_decode($metaJson, true);
        if (!is_array($meta)) {
            WP_CLI::warning("Estimate {$estimateId} has invalid meta data.");
            return;
        }

        $payments = $meta['payment']['payments'] ?? [];
        if (empty($payments)) {
            WP_CLI::log("No payment records found for estimate {$estimateId}.");
            return;
        }

        WP_CLI::log("Found " . count($payments) . " payment record(s)");

        // Step 1: Deduplicate payments
        $deduplicated = $this->deduplicatePayments($payments);
        $duplicatesRemoved = count($payments) - count($deduplicated);
        
        if ($duplicatesRemoved > 0) {
            WP_CLI::log("Removed {$duplicatesRemoved} duplicate payment record(s)");
        }

        // Step 2: Recalculate totals
        $invoice = $meta['invoice'] ?? [];
        $invoiceTotal = (float) ($invoice['total'] ?? $invoice['amount'] ?? 0);
        
        $totalPaidAmount = 0;
        foreach ($deduplicated as $p) {
            $isSuccessful = ($p['status'] ?? 'succeeded') === 'succeeded';
            $isRefunded = ($p['refunded'] ?? false) === true;
            if ($isSuccessful && !$isRefunded && !empty($p['amount'])) {
                $totalPaidAmount += (float) $p['amount'];
            }
        }

        $isFullyPaid = abs($totalPaidAmount - $invoiceTotal) < 0.01;
        $remainingBalance = max(0, $invoiceTotal - $totalPaidAmount);

        WP_CLI::log("Recalculated totals:");
        WP_CLI::log("  Invoice Total: " . number_format($invoiceTotal, 2));
        WP_CLI::log("  Total Paid: " . number_format($totalPaidAmount, 2));
        WP_CLI::log("  Remaining Balance: " . number_format($remainingBalance, 2));
        WP_CLI::log("  Fully Paid: " . ($isFullyPaid ? 'Yes' : 'No'));

        // Step 3: Update payment object
        $payment = $meta['payment'] ?? [];
        $payment['payments'] = $deduplicated;
        $payment['amount'] = $totalPaidAmount;
        $payment['status'] = $isFullyPaid ? 'paid' : ($totalPaidAmount > 0 ? 'partial' : 'pending');
        $payment['remainingBalance'] = $remainingBalance;

        // Step 4: Update invoice meta
        $invoiceMeta = $invoice;
        $invoiceMeta['amountDue'] = $remainingBalance;
        $invoiceMeta['status'] = $isFullyPaid ? 'paid' : ($totalPaidAmount > 0 ? 'partial' : ($invoiceMeta['status'] ?? 'draft'));

        // Step 5: Update workflow
        $workflow = $meta['workflow'] ?? [];
        if ($isFullyPaid) {
            $workflow['status'] = 'paid';
            $workflow['currentStep'] = 5;
            if (empty($workflow['paidAt'])) {
                $workflow['paidAt'] = current_time('mysql');
            }
        } else {
            $workflow['status'] = 'booked';
        }

        // Step 6: Save changes
        if ($dryRun) {
            WP_CLI::log("\n=== DRY RUN - No changes saved ===");
            WP_CLI::log("Would update:");
            WP_CLI::log("  payment.status: " . ($payment['status'] ?? 'N/A'));
            WP_CLI::log("  payment.amount: " . number_format($payment['amount'] ?? 0, 2));
            WP_CLI::log("  payment.remainingBalance: " . number_format($payment['remainingBalance'] ?? 0, 2));
            WP_CLI::log("  invoice.status: " . ($invoiceMeta['status'] ?? 'N/A'));
            WP_CLI::log("  invoice.amountDue: " . number_format($invoiceMeta['amountDue'] ?? 0, 2));
            WP_CLI::log("  workflow.status: " . ($workflow['status'] ?? 'N/A'));
        } else {
            $this->portalService->updateMeta($estimateId, [
                'payment' => $payment,
                'invoice' => $invoiceMeta,
                'workflow' => $workflow,
            ]);
            WP_CLI::success("Repaired estimate {$estimateId}");
        }
    }

    /**
     * Deduplicate payments by paymentIntentId/transactionId
     */
    private function deduplicatePayments(array $payments): array
    {
        $seen = [];
        $deduplicated = [];

        foreach ($payments as $payment) {
            // Use paymentIntentId as primary key, transactionId as fallback
            $key = $payment['paymentIntentId'] ?? $payment['transactionId'] ?? null;
            
            if (empty($key)) {
                // No key - keep it but log warning
                WP_CLI::warning("Payment record without paymentIntentId or transactionId found - keeping it");
                $deduplicated[] = $payment;
                continue;
            }

            if (isset($seen[$key])) {
                // Duplicate found - merge data, preferring the one with more complete info
                $existing = $seen[$key];
                $merged = $this->mergePaymentRecords($existing, $payment);
                // Update in deduplicated array
                $index = array_search($existing, $deduplicated, true);
                if ($index !== false) {
                    $deduplicated[$index] = $merged;
                }
                WP_CLI::log("Merged duplicate payment: {$key}");
            } else {
                // New payment - add it
                $seen[$key] = $payment;
                $deduplicated[] = $payment;
            }
        }

        return $deduplicated;
    }

    /**
     * Merge two payment records, preferring the one with more complete info
     */
    private function mergePaymentRecords(array $record1, array $record2): array
    {
        // Prefer record with xeroPaymentId
        if (!empty($record1['xeroPaymentId']) && empty($record2['xeroPaymentId'])) {
            return $record1;
        }
        if (!empty($record2['xeroPaymentId']) && empty($record1['xeroPaymentId'])) {
            return $record2;
        }

        // Prefer record with more fields (count non-empty values)
        $record1Fields = count(array_filter($record1, fn($v) => $v !== null && $v !== '' && $v !== false));
        $record2Fields = count(array_filter($record2, fn($v) => $v !== null && $v !== '' && $v !== false));

        if ($record1Fields >= $record2Fields) {
            return array_merge($record2, $record1); // record1 wins, but merge in any missing fields from record2
        } else {
            return array_merge($record1, $record2); // record2 wins
        }
    }

    /**
     * Repair all estimates
     */
    private function repairAllEstimates(bool $dryRun): void
    {
        WP_CLI::log("Scanning for all estimates with payment records...");

        // Get all portal meta options
        global $wpdb;
        $optionPrefix = 'ca_portal_meta_';
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
                $optionPrefix . '%'
            ),
            ARRAY_A
        );

        if (empty($results)) {
            WP_CLI::log("No estimates found.");
            return;
        }

        $estimateIds = [];
        foreach ($results as $row) {
            $estimateId = str_replace($optionPrefix, '', $row['option_name']);
            $estimateIds[] = $estimateId;
        }

        WP_CLI::log("Found " . count($estimateIds) . " estimate(s)");

        $repaired = 0;
        $skipped = 0;

        foreach ($estimateIds as $estimateId) {
            $metaJson = get_option('ca_portal_meta_' . $estimateId, null);
            if (empty($metaJson)) {
                $skipped++;
                continue;
            }
            
            $meta = json_decode($metaJson, true);
            if (!is_array($meta)) {
                $skipped++;
                continue;
            }
            
            $payments = $meta['payment']['payments'] ?? [];
            
            if (empty($payments)) {
                $skipped++;
                continue;
            }

            try {
                $this->repairEstimate($estimateId, $dryRun);
                $repaired++;
            } catch (\Exception $e) {
                WP_CLI::warning("Failed to repair estimate {$estimateId}: " . $e->getMessage());
            }
        }

        WP_CLI::log("\n=== Summary ===");
        WP_CLI::log("Repaired: {$repaired}");
        WP_CLI::log("Skipped: {$skipped}");
        WP_CLI::log("Total: " . count($estimateIds));
    }
}
