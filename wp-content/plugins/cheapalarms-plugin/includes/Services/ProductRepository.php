<?php

namespace CheapAlarms\Plugin\Services;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Minimal product repository backed by wp_options.
 *
 * Stores a single associative array option where keys are product IDs and values
 * are product payloads (arrays). This is sufficient for a prototype. Replace with
 * CPT or custom tables later without changing controllers.
 */
class ProductRepository
{
    private const OPTION_KEY = 'ca_products';

    /**
     * @return array<string,array> id => product
     */
    public function all(): array
    {
        $data = get_option(self::OPTION_KEY, []);
        return is_array($data) ? $data : [];
    }

    /**
     * @param string $id
     * @return array|null
     */
    public function get(string $id): ?array
    {
        $all = $this->all();
        return $all[$id] ?? null;
    }

    /**
     * @param array $product
     * @return array The saved product
     */
    public function save(array $product): array
    {
        $all = $this->all();
        $id = isset($product['id']) && is_string($product['id']) && $product['id'] !== ''
            ? $product['id']
            : $this->generateId($product['name'] ?? 'item');

        $product['id'] = $id;
        $product['updatedAt'] = gmdate('c');
        if (!isset($product['createdAt'])) {
            $product['createdAt'] = $product['updatedAt'];
        }
        $all[$id] = $product;
        update_option(self::OPTION_KEY, $all, false);
        return $product;
    }

    /**
     * @param string $id
     * @return bool
     */
    public function delete(string $id): bool
    {
        $all = $this->all();
        if (!isset($all[$id])) {
            return false;
        }
        unset($all[$id]);
        update_option(self::OPTION_KEY, $all, false);
        return true;
    }

    private function generateId(string $seed): string
    {
        $base = sanitize_title($seed);
        $rand = wp_generate_password(6, false, false);
        return $base !== '' ? "{$base}_{$rand}" : "item_{$rand}";
    }
}


