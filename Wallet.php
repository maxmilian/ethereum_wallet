<?php

require_once "vendor/autoload.php";

use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoEncoding\PEM;
use kornrunner\keccak;

class Wallet
{
    public function create(): string
    {
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp256k1'
        ];

        $res = openssl_pkey_new($config);
        if (!$res) {
            echo 'ERROR: Fail to generate private key. -> ' . openssl_error_string();
            exit;
        }
        // Generate Private Key
        openssl_pkey_export($res, $priv_key);
        // Get The Public Key
        $key_detail = openssl_pkey_get_details($res);
        $pub_key = $key_detail["key"];
        $priv_pem = PEM::fromString($priv_key);
        // Convert to Elliptic Curve Private Key Format
        $ec_priv_key = ECPrivateKey::fromPEM($priv_pem);
        // Then convert it to ASN1 Structure
        $ec_priv_seq = $ec_priv_key->toASN1();
        // Private Key & Public Key in HEX
        $priv_key_hex = bin2hex($ec_priv_seq->at(1)->asOctetString()->string());
        $priv_key_len = strlen($priv_key_hex) / 2;
        $pub_key_hex = bin2hex($ec_priv_seq->at(3)->asTagged()->asExplicit()->asBitString()->string());
        $pub_key_len = strlen($pub_key_hex) / 2;
        // Derive the Ethereum Address from public key
        // Every EC public key will always start with 0x04,
        // we need to remove the leading 0x04 in order to hash it correctly
        $pub_key_hex_2 = substr($pub_key_hex, 2);
        $pub_key_len_2 = strlen($pub_key_hex_2) / 2;
        // Hash time
        $hash = Keccak::hash(hex2bin($pub_key_hex_2), 256);
        // Ethereum address has 20 bytes length. (40 hex characters long)
        // We only need the last 20 bytes as Ethereum address
        $wallet_address = '0x' . substr($hash, -40);
        $wallet_private_key = '0x' . $priv_key_hex;
        echo "ETH Wallet Address: " . $wallet_address . PHP_EOL;
        echo "Private Key: " . $wallet_private_key . PHP_EOL;

        return $wallet_address;
    }

    public function validate(String $address): bool
    {
        if ($this->matchesPattern($address)) {
            return $this->isAllSameCaps($address) ?: $this->isValidChecksum($address);
        }

        return false;
    }

    protected function matchesPattern(string $address): int
    {
        return preg_match('/^(0x)?[0-9a-f]{40}$/i', $address);
    }

    protected function isAllSameCaps(string $address): bool
    {
        return preg_match('/^(0x)?[0-9a-f]{40}$/', $address) || preg_match('/^(0x)?[0-9A-F]{40}$/', $address);
    }

    protected function isValidChecksum($address)
    {
        $address = str_replace('0x', '', $address);
        // See: https://github.com/ethereum/web3.js/blob/b794007/lib/utils/sha3.js#L35
        $hash = Sha3::hash(strtolower($address), 256);

        // See: https://github.com/web3j/web3j/pull/134/files#diff-db8702981afff54d3de6a913f13b7be4R42
        for ($i = 0; $i < 40; $i++) {
            if (ctype_alpha($address{$i})) {
                // Each uppercase letter should correlate with a first bit of 1 in the hash char with the same index,
                // and each lowercase letter with a 0 bit.
                $charInt = intval($hash{$i}, 16);

                if ((ctype_upper($address{$i}) && $charInt <= 7) || (ctype_lower($address{$i}) && $charInt > 7)) {
                    return false;
                }
            }
        }

        return true;
    }
}
