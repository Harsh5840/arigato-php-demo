<?php

declare(strict_types=1);

use SakuraShop\Storefront;

require __DIR__ . '/../src/Storefront.php';

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$store = new Storefront();

if ($method === 'GET' && $path === '/') {
    header('Content-Type: text/html; charset=UTF-8');
    $products = $store->handle('GET', '/api/products')['body']['products'];
    ?>
<!doctype html>
<html lang="ja">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SakuraShop · local security demo</title>
<style>
body{margin:0;background:#f8f5ef;color:#242723;font:18px/1.6 system-ui,sans-serif}main{max-width:850px;margin:64px auto;padding:24px}.label{color:#8d2042;font-size:14px;font-weight:700}h1{font-size:48px;line-height:1.1;margin:20px 0}.notice{padding:16px;border:1px solid #b97838;background:#fff0df;font-size:15px}.products{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:32px 0}article{background:white;padding:24px;border:1px solid #d9d8cf}h2{font-size:21px}a{color:#235742}code{font-size:14px}footer{font-size:14px;color:#555}
</style>
<main>
  <span class="label">架空の日本の小さなお店 / FICTIONAL JAPANESE SME</span>
  <h1>SakuraShop<br>日常に、ひとさじの日本。</h1>
  <p class="notice">Local hackathon fixture. The baseline declares an intentionally affected PHP runtime. Do not deploy. No exploit is included.</p>
  <div class="products">
  <?php foreach ($products as $product): ?>
    <article><h2><?= htmlspecialchars($product['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></h2><p>¥<?= number_format($product['price_yen']) ?> <small>税込</small></p></article>
  <?php endforeach; ?>
  </div>
  <p>Read-only fixture: <a href="/api/products">products API</a> · <a href="/health">health</a></p>
  <footer>Orders require one of the public seeded demo bearer tokens in README. All amounts are integer JPY; tax is already included. No payments, customer data or external services.</footer>
</main>
</html>
    <?php
    exit;
}

$result = $store->handle($method, is_string($path) ? $path : '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');
http_response_code($result['status']);
header('Content-Type: application/json; charset=UTF-8');
if ($result['status'] === 405) {
    header('Allow: GET');
}
echo json_encode($result['body'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
