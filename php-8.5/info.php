<?php
header('Content-Type: text/plain');
$keys = ['file_uploads', 'memory_limit', 'post_max_size', 'max_file_uploads',
         'max_input_vars', 'max_input_nesting_level', 'session.upload_progress.enabled'];
if (PHP_VERSION_ID >= 80500) $keys[] = 'fatal_error_backtraces';
echo "PHP_VERSION=" . PHP_VERSION . "\nSAPI=" . PHP_SAPI . "\n";
foreach ($keys as $k) echo "$k=" . var_export(ini_get($k), true) . "\n";
echo "method=" . $_SERVER['REQUEST_METHOD'] . " post_fields=" . count($_POST) . " files=" . count($_FILES) . "\n";
