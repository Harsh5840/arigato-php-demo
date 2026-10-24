<?php

declare(strict_types=1);

namespace SakuraShop;

/** Read-only seeded fixture. Public demo tokens are not production authentication. */
final class Storefront
{
    private const PRODUCTS = [
        'matcha' => ['id' => 'matcha', 'name' => '京都の抹茶セット', 'price_yen' => 2400],
        'notebook' => ['id' => 'notebook', 'name' => '桜ノート', 'price_yen' => 880],
        'tote' => ['id' => 'tote', 'name' => '和柄トートバッグ', 'price_yen' => 1800],
    ];

    private const CUSTOMERS = [
        'sakura-demo-tokyo' => ['id' => 'customer-tokyo', 'name' => '田中 花子', 'city' => '東京都'],
        'sakura-demo-osaka' => ['id' => 'customer-osaka', 'name' => '佐藤 健', 'city' => '大阪市'],
    ];

    private const ORDERS = [
        'order-tokyo-001' => ['customer_id' => 'customer-tokyo', 'items' => [['product_id' => 'matcha', 'quantity' => 2]]],
        'order-osaka-001' => ['customer_id' => 'customer-osaka', 'items' => [['product_id' => 'notebook', 'quantity' => 3]]],
    ];

    /** @return array{status: int, body: array<string, mixed>} */
    public function handle(string $method, string $path, string $authorization = ''): array
    {
        if ($method !== 'GET') {
            return $this->response(405, ['error' => 'method_not_allowed']);
        }

        if ($path === '/health') {
            return $this->response(200, ['status' => 'ok', 'fixture' => true, 'store' => 'SakuraShop']);
        }

        if ($path === '/api/products') {
            return $this->response(200, ['currency' => 'JPY', 'tax_included' => true, 'products' => array_values(self::PRODUCTS)]);
        }

        if ($path === '/api/me' || str_starts_with($path, '/api/orders/')) {
            $customer = $this->customerFor($authorization);
            if ($customer === null) {
                return $this->response(401, ['error' => 'unauthorized']);
            }

            if ($path === '/api/me') {
                return $this->response(200, ['customer' => $customer]);
            }

            $orderId = substr($path, strlen('/api/orders/'));
            $order = self::ORDERS[$orderId] ?? null;
            if ($order === null || $order['customer_id'] !== $customer['id']) {
                return $this->response(404, ['error' => 'order_not_found']);
            }

            $totalYen = 0;
            $items = [];
            foreach ($order['items'] as $item) {
                $product = self::PRODUCTS[$item['product_id']];
                $lineTotal = $product['price_yen'] * $item['quantity'];
                $totalYen += $lineTotal;
                $items[] = [...$product, 'quantity' => $item['quantity'], 'line_total_yen' => $lineTotal];
            }

            return $this->response(200, [
                'id' => $orderId,
                'customer_id' => $customer['id'],
                'currency' => 'JPY',
                'tax_included' => true,
                'items' => $items,
                'total_yen' => $totalYen,
            ]);
        }

        return $this->response(404, ['error' => 'not_found']);
    }

    /** @return array{id: string, name: string, city: string}|null */
    private function customerFor(string $authorization): ?array
    {
        if (preg_match('/\ABearer ([a-z0-9-]+)\z/i', $authorization, $matches) !== 1) {
            return null;
        }

        foreach (self::CUSTOMERS as $token => $customer) {
            if (hash_equals($token, $matches[1])) {
                return $customer;
            }
        }

        return null;
    }

    /** @param array<string, mixed> $body
     *  @return array{status: int, body: array<string, mixed>}
     */
    private function response(int $status, array $body): array
    {
        return ['status' => $status, 'body' => $body];
    }
}
