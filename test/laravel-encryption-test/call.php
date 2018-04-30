<?php
require __DIR__ . '/vendor/autoload.php';
unset($argv[0]);
$opts = json_decode(implode('', $argv));

$encrypter = new \Illuminate\Encryption\Encrypter($opts->key);

echo json_encode(call_user_func_array([$encrypter, $opts->method], $opts->params));