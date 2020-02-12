<?php

namespace Afosto\LetsEncrypt;

use Afosto\LetsEncrypt\Data\Authorization;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;

class Helper
{

    /**
     * Formatter
     * @param $pem
     * @return false|string
     */
    public static function toDer($pem)
    {
        $lines = explode(PHP_EOL, $pem);
        $lines = array_slice($lines, 1, -1);

        return base64_decode(implode('', $lines));
    }

    /**
     * Return certificate expiry date
     *
     * @param $certificate
     *
     * @return \DateTime
     * @throws \Exception
     */
    public static function getCertExpiryDate($certificate): \DateTime
    {
        $info = openssl_x509_parse($certificate);
        if ($info === false) {
            throw new \Exception('Could not parse certificate');
        }
        $dateTime = new \DateTime();
        $dateTime->setTimestamp($info['validTo_time_t']);

        return $dateTime;
    }

    /**
     * Get a new key
     *
     * @return string
     */
    public static function getNewKey(): string
    {

        $key = openssl_pkey_new([
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    /**
     * Get a new CSR
     *
     * @param array $domains
     * @param       $key
     *
     * @return string
     * @throws \Exception
     */
    public static function getCsr(array $domains, $key): string
    {
        $primaryDomain = current(($domains));
        $config = [
            '[req]',
            'distinguished_name=req_distinguished_name',
            '[req_distinguished_name]',
            '[v3_req]',
            '[v3_ca]',
            '[SAN]',
            'subjectAltName=' . implode(',', array_map(function ($domain) {
                return 'DNS:' . $domain;
            }, $domains)),
        ];

        $fn = tempnam(sys_get_temp_dir(), md5(microtime(true)));
        file_put_contents($fn, implode("\n", $config));
        $csr = openssl_csr_new([
            'countryName' => 'NL',
            'commonName'  => $primaryDomain,
        ], $key, [
            'config'         => $fn,
            'req_extensions' => 'SAN',
            'digest_alg'     => 'sha512',
        ]);
        unlink($fn);

        if ($csr === false) {
            throw new \Exception('Could not create a CSR');
        }

        if (openssl_csr_export($csr, $result) == false) {
            throw new \Exception('CRS export failed');
        }

        $result = trim($result);

        return $result;
    }

    /**
     * Make a safe base64 string
     *
     * @param $data
     *
     * @return string
     */
    public static function toSafeString($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Get the key information
     *
     * @return array
     * @throws \Exception
     */
    public static function getKeyDetails($key): array
    {
        $accountDetails = openssl_pkey_get_details($key);
        if ($accountDetails === false) {
            throw new \Exception('Could not load account details');
        }

        return $accountDetails;
    }
}
