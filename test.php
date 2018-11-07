<?php

require_once "Wallet.php";

$wallet = new Wallet();

$address = $wallet->create();
echo "address: {$address}".PHP_EOL;

echo "validate: ";
var_dump($wallet->validate($address));
