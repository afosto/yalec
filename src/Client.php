<?php

namespace Afosto\LetsEncrypt;

use Afosto\LetsEncrypt\Data\Account;
use Afosto\LetsEncrypt\Data\Authorization;
use Afosto\LetsEncrypt\Data\Certificate;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;
use League\Flysystem\Filesystem;
use Psr\Http\Message\ResponseInterface;

class Client
{
    /**
     * Live url
     */
    const DIRECTORY_LIVE = 'https://acme-v01.api.letsencrypt.org/directory';

    /**
     * Staging url
     */
    const DIRECTORY_STAGING = 'https://acme-staging.api.letsencrypt.org/directory';

    /**
     * Flag for production
     */
    const MODE_LIVE = 'live';

    /**
     * Flag for staging
     */
    const MODE_STAGING = 'staging';

    /**
     * Account directory
     */
    const DIRECTORY_REGISTER = 'new-reg';

    /**
     * Authorization directory
     */
    const DIRECTORY_AUTHZ = 'new-authz';

    /**
     * Account directory
     */
    const DIRECTORY_USER = 'reg';

    /**
     * Challenge directory
     */
    const DIRECTORY_CHALLENGE = 'challenge';

    /**
     * Certificate directory
     */
    const DIRECTORY_NEW_CERT = 'new-cert';

    /**
     * Http validation
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * @var string
     */
    protected $nonce;

    /**
     * @var string
     */
    protected $accountKey;

    /**
     * @var Filesystem
     */
    protected $filesystem;

    /**
     * @var array
     */
    protected $directories = [];

    /**
     * @var array
     */
    protected $accountDetails = [];

    /**
     * @var array
     */
    protected $header = [];

    /**
     * @var string
     */
    protected $thumbPrint;

    /**
     * @var HttpClient
     */
    protected $httpClient;

    /**
     * AcmeClient constructor.
     *
     * @param array     $config   {
     *
     * @type string     $mode     The mode for ACME (production / staging)
     * @type Filesystem $fs       Filesystem for storage of static data
     * @type string     $basePath The base path for the filesystem (used to store account information and csr / keys
     * @type string     $username The acme username
     * }
     */
    public function __construct($config = [])
    {
        $this->options = $config;
        $this->httpClient = new HttpClient([
            'base_uri' => (
            ($this->getOption('mode', self::MODE_LIVE) == self::MODE_LIVE) ?
                self::DIRECTORY_LIVE : self::DIRECTORY_STAGING),
        ]);

        if ($this->getOption('fs', false)) {
            $this->filesystem = $this->getOption('fs');
        } else {
            throw new \LogicException('No filesystem option supplied');
        }

        if ($this->getOption('username', false) === false) {
            throw new \LogicException('Username not provided');
        }

        $this->init();
    }

    /**
     * @return Account
     */
    public function getAccount()
    {
        $payload = [
            'contact' => [
                'mailto:' . $this->getOption('username'),
            ],
        ];
        $account = new Account();

        try {
            $response = $this->request(self::DIRECTORY_REGISTER, $payload);

            $account->setAccountReference(current($response->getHeader('location')));
        } catch (ClientException $e) {
            $account->setAccountReference(current($e->getResponse()->getHeader('location')));
            if ($e->getResponse()->getStatusCode() == '409') {
                $response = $this->request(self::DIRECTORY_USER, $payload, $account->getAccountReference());

                $result = \GuzzleHttp\json_decode((string)$response->getBody(), true);
                $account->setHasAgreement(isset($result['agreement']));
            } else {
                throw $e;
            }
        }
        foreach ($response->getHeader('link') as $header) {
            if (strpos($header, 'terms-of-service') !== false) {
                $account->setTos(Helper::stripLinkTags($header));
            }
        }

        return $account;
    }

    /**
     * @param Account $account
     *
     * @return $this
     */
    public function agree(Account $account)
    {
        if ($account->getHasAgreement() === true) {
            return $this;
        }
        $payload = [
            'contact'   => [
                'mailto:' . $this->getOption('username'),
            ],
            'agreement' => $account->getTos(),
        ];
        $this->request(self::DIRECTORY_USER, $payload, $account->getAccountReference());

        return $this;
    }

    /**
     * Attempt an authorization for the given domains
     *
     * @param array $domains
     *
     * @return Authorization[]
     */
    public function authorize(array $domains)
    {
        $authorizations = [];
        foreach ($domains as $domain) {
            $response = $this->request(self::DIRECTORY_AUTHZ, [
                'identifier' => [
                    'type'  => 'dns',
                    'value' => $domain,
                ],
            ]);
            $result = \GuzzleHttp\json_decode((string)$response->getBody(), true);

            $authorization = new Authorization($this->getThumbprint());
            $authorization->setExpires((new \DateTime())->setTimestamp(strtotime($result['expires'])));
            $authorization->setIdentifier($result['identifier']['type'], $result['identifier']['value']);

            foreach ($result['challenges'] as $challenge) {
                $authorization->addChallenge($challenge['type'], $challenge['status'], $challenge['token'],
                    $challenge['uri']);
            }
            $authorizations[] = $authorization;
        }

        return $authorizations;
    }

    /**
     * @param Authorization[] $authorizations
     * @param int             $retries
     * @param string          $type
     *
     * @return bool
     */
    public function validate(array $authorizations, $retries = 5, $type = self::VALIDATION_HTTP)
    {

        foreach ($authorizations as $authorization) {
            $success = false;
            while ($retries > 0) {
                if ($this->requestValidation($authorization, $type) && Helper::isValid($authorization, $type)) {
                    $success = true;
                    break;
                }
                sleep(1);
            }

            if ($success === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array $domains
     * @param null  $primaryDomain
     *
     * @return Certificate
     */
    public function getCertificate(array $domains, $primaryDomain = null)
    {
        if ($primaryDomain === null) {
            $primaryDomain = current($domains);
        }
        $certificate = new Certificate();
        $certificate->setPrivateKey(Helper::getNewKey());
        $certificate->setCsr(Helper::getCsr($domains, $primaryDomain, $certificate->getPrivateKey()));

        $der = Helper::toDer($certificate->getCsr());
        $response = $this->request(self::DIRECTORY_NEW_CERT, [
            'csr' => Helper::toSafeString($der),
        ]);
        $bundle = Helper::toPem((string)$response->getBody());
        $bundle .= Helper::getIntermediate(Helper::stripLinkTags(current($response->getHeader('link'))));

        $certificate->setCertificate($bundle);

        return $certificate;
    }

    /**
     * @param Authorization $authorization
     * @param string        $type
     *
     * @return bool
     */
    protected function requestValidation(Authorization $authorization, $type = self::VALIDATION_HTTP)
    {
        if ($type == self::VALIDATION_HTTP && Helper::selfTest($authorization) === false) {
            return false;
        }
        foreach ($authorization->getChallenges() as $challenge) {
            if ($challenge->getType() == $type) {
                $this->request(
                    self::DIRECTORY_CHALLENGE,
                    [
                        'keyAuthorization' => $challenge->getToken() . '.' . $this->getThumbprint(),
                    ],
                    $challenge->getUri()
                );

                return true;
            }
        }

        return false;
    }

    /**
     * @param null $path
     *
     * @return string
     */
    protected function getPath($path = null)
    {
        $userDirectory = preg_replace('/[^a-z0-9]+/', '-', strtolower($this->getOption('username')));

        return $this->getOption(
                'basePath',
                'le'
            ) . DIRECTORY_SEPARATOR . $userDirectory . ($path === null ? '' : DIRECTORY_SEPARATOR . $path);
    }

    /**
     * @return Filesystem
     */
    protected function getFilesystem()
    {
        return $this->filesystem;
    }

    /**
     * @param      $key
     * @param null $default
     *
     * @return mixed|null
     */
    protected function getOption($key, $default = null)
    {
        if (isset($this->options[$key])) {
            return $this->options[$key];
        }

        return $default;
    }

    /**
     * @param       $directory
     * @param array $payload
     * @param null  $url
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function request($directory, $payload = [], $url = null)
    {
        $method = 'POST';
        if (empty($payload)) {
            $method = 'GET';
        }

        if ($url === null) {
            $url = $this->getUrl($directory);
        }
        try {
            $response = $this->httpClient->request($method, $url, [
                'json' => $this->signPayload($payload, $directory),
            ]);
            $this->updateNonce($response);
        } catch (ClientException $e) {
            $this->updateNonce($e->getResponse());
            throw $e;
        }

        return $response;
    }

    /**
     * @return string
     */
    protected function getThumbprint()
    {

        if ($this->thumbPrint === null) {
            $this->thumbPrint =
                Helper::toSafeString(hash('sha256', json_encode($this->getHeader()['jwk']), true));
        }

        return $this->thumbPrint;
    }

    /**
     * @param ResponseInterface $response
     */
    protected function updateNonce(ResponseInterface $response)
    {
        $newNonce = current($response->getHeader('replay-nonce'));
        if ($newNonce !== null) {
            $this->nonce = $newNonce;
        }
    }

    /**
     * Get the LE directory path
     *
     * @param $directory
     *
     * @return mixed
     * @throws \Exception
     */
    protected function getUrl($directory)
    {
        if (isset($this->directories[$directory])) {
            return $this->directories[$directory];
        }

        throw new \Exception('Invalid directory: ' . $directory . ' not listed');
    }

    /**
     * Initialize the client
     */
    protected function init()
    {
        $response = $this->httpClient->get('');
        $result = \GuzzleHttp\json_decode((string)$response->getBody(), true);

        $this->directories = $result;
        $this->nonce = current($response->getHeader('replay-nonce'));

        if ($this->getFilesystem()->has($this->getPath('account.pem')) === false) {
            $this->getFilesystem()->write($this->getPath('account.pem'), Helper::getNewKey());
        }

        $this->agree($this->getAccount());
    }

    /**
     * Get the key
     *
     * @return bool|resource|string
     * @throws \Exception
     */
    protected function getAccountKey()
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private($this->getFilesystem()
                                                              ->read($this->getPath('account.pem')));
        }

        if ($this->accountKey === false) {
            throw new \Exception('Invalid account key');
        }

        return $this->accountKey;
    }

    /**
     * Get the header
     *
     * @return array
     */
    protected function getHeader()
    {
        if (empty($this->header)) {
            $this->header = [
                'alg' => 'RS256',
                'jwk' => [
                    'e'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['e']),
                    'kty' => 'RSA',
                    'n'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['n']),
                ],
            ];
        }

        return $this->header;
    }

    /**
     * Transform the payload to the JWS format
     *
     * @param $payload
     *
     * @return array
     * @throws \Exception
     */
    protected function signPayload($payload, $type)
    {
        $payload = array_merge($payload, ['resource' => $type]);

        $payload = Helper::toSafeString(json_encode($payload));
        $header = $this->getHeader();
        $header['nonce'] = $this->nonce;
        $protected = Helper::toSafeString(json_encode($header));

        $result = openssl_sign(
            $protected . '.' . $payload,
            $signature,
            $this->getAccountKey(),
            OPENSSL_ALGO_SHA256
        );

        if ($result === false) {
            throw new \Exception('Could not sign');
        }

        return [
            'header'    => $this->getHeader(),
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }
}
