<?php

declare(strict_types=1);

$checks = [
    'runtime_matches_reviewed_release' => PHP_VERSION === '8.3.36',
    'upload_progress_disabled_at_startup' => in_array((string) ini_get('session.upload_progress.enabled'), ['', '0'], true),
    'expected_serializer' => ini_get('session.serialize_handler') === 'php',
];
echo json_encode([
    'evidence_class' => 'observed_runtime_configuration',
    'php_version' => PHP_VERSION,
    'upload_progress_enabled' => ini_get('session.upload_progress.enabled'),
    'serialize_handler' => ini_get('session.serialize_handler'),
    'checks' => $checks,
    'limitation' => 'No exploit was executed. Deployment and worker restart are not verified by this CLI probe.',
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
exit(in_array(false, $checks, true) ? 1 : 0);
