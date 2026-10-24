<?php

declare(strict_types=1);

use SakuraShop\Storefront;

require __DIR__ . '/../src/Storefront.php';

$store = new Storefront();
$checks = 0;
$expect = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$label}\n");
        exit(1);
    }
    $checks++;
    fwrite(STDOUT, "PASS: {$label}\n");
};

$products = $store->handle('GET', '/api/products');
$expect($products['status'] === 200 && count($products['body']['products']) === 3, 'catalog remains available');
$expect($products['body']['currency'] === 'JPY', 'catalog currency is JPY');
foreach ($products['body']['products'] as $product) {
    $expect(is_int($product['price_yen']) && $product['price_yen'] > 0, "integer yen price: {$product['id']}");
}
$json = json_encode($products['body'], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
$expect(str_contains($json, '京都の抹茶セット'), 'Japanese UTF-8 product text survives JSON encoding');
$expect($store->handle('GET', '/api/orders/order-tokyo-001')['status'] === 401, 'anonymous order access is denied');
$expect($store->handle('GET', '/api/orders/order-tokyo-001', 'Bearer invalid')['status'] === 401, 'invalid token is denied');
$owner = $store->handle('GET', '/api/orders/order-tokyo-001', 'Bearer sakura-demo-tokyo');
$expect($owner['status'] === 200, 'Tokyo customer can read own order');
$expect($owner['body']['total_yen'] === 4800 && is_int($owner['body']['total_yen']), 'two matcha sets total exactly 4800 integer yen');
$expect($owner['body']['items'][0]['line_total_yen'] === 4800, 'line totals agree with order total');
$crossOwner = $store->handle('GET', '/api/orders/order-tokyo-001', 'Bearer sakura-demo-osaka');
$missing = $store->handle('GET', '/api/orders/not-present', 'Bearer sakura-demo-osaka');
$expect($crossOwner['status'] === 404 && $crossOwner['body'] === $missing['body'], 'other customer cannot read or distinguish the order');
$otherOwner = $store->handle('GET', '/api/orders/order-osaka-001', 'Bearer sakura-demo-osaka');
$expect($otherOwner['status'] === 200 && $otherOwner['body']['total_yen'] === 2640, 'Osaka customer still receives correct own order');
$expect($store->handle('POST', '/api/orders/order-tokyo-001', 'Bearer sakura-demo-tokyo')['status'] === 405, 'read-only fixture rejects mutations');
$expect($store->handle('GET', '/api/me', 'Bearer sakura-demo-tokyo')['body']['customer']['city'] === '東京都', 'authenticated Japanese customer profile survives');
fwrite(STDOUT, "{$checks} business checks passed. This is application behavior evidence, not PHP RCE proof.\n");
