<?php

namespace Afosto\LetsEncrypt;

use Afosto\LetsEncrypt\Data\Authorization;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;

class Helper
{

    public static function toDer($pem)
    {

        $lines = explode(PHP_EOL, $pem);
        $lines = array_slice($lines, 1, -1);

        return base64_decode(implode('', $lines));
    }

    public static function toPem($der)
    {
        return '-----BEGIN CERTIFICATE-----' . PHP_EOL
            . chunk_split(base64_encode($der), 64, PHP_EOL)
            . '-----END CERTIFICATE-----' . PHP_EOL;
    }

    /**
     * @param $link
     *
     * @return bool|string
     */
    public static function stripLinkTags($link)
    {
        return substr($link, strpos($link, '<') + 1, strpos($link, '>') - 1);
    }

    /**
     * @return string
     */
    public static function getNewKey()
    {

        $key = openssl_pkey_new([
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    /**
     * @param array $domains
     * @param       $primaryDomain
     * @param       $key
     *
     * @return string
     * @throws \Exception
     */
    public static function getCsr(array $domains, $primaryDomain, $key)
    {
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
    public static function toSafeString($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Get the key information
     *
     * @return array
     * @throws \Exception
     */
    public static function getKeyDetails($key)
    {
        $accountDetails = openssl_pkey_get_details($key);
        if ($accountDetails === false) {
            throw new \Exception('Could not load account details');
        }

        return $accountDetails;
    }

    /**
     * @param Authorization $authorization
     * @param string        $type
     *
     * @return bool
     */
    public static function isValid(Authorization $authorization, $type = Client::VALIDATION_HTTP)
    {
        foreach ($authorization->getChallenges() as $challenge) {
            if ($challenge->getType() == $type) {
                $client = new HttpClient();
                $response = $client->get($challenge->getUri());

                $result = \GuzzleHttp\json_decode((string)$response->getBody(), true);

                return $result['status'] == 'valid';
            }
        }

        return false;
    }

    /**
     * @param Authorization $authorization
     *
     * @return bool
     */
    public static function selfTest(Authorization $authorization)
    {
        try {
            $client = new HttpClient();
            $url = $authorization->getIdentifier()->getValue() .
                '/.well-known/acme-challenge/' . $authorization->getFile()->getFilename();

            $client->get($url, [
                'allow_redirects' => true,
                'protocols'       => ['http', 'https'],
            ]);
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() == 404) {
                return false;
            }
        }
    }

    /**
     *
     * @return string
     */
    public static function getIntermediate($url)
    {
        $client = new HttpClient();
        $response = $client->get($url);
        $intermediateCertificate = Helper::toPem((string)$response->getBody());

        return $intermediateCertificate;
    }
}
