<?php

namespace Afosto\LetsEncrypt\Data;

class Certificate
{

    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $certificate;

    /**
     * @var string
     */
    protected $csr;

    /**
     * @param $key
     *
     * @return $this
     */
    public function setPrivateKey($key)
    {
        $this->privateKey = $key;

        return $this;
    }

    /**
     * @param $csr
     *
     * @return $this
     */
    public function setCsr($csr)
    {
        $this->csr = $csr;

        return $this;
    }

    /**
     * @param $certificate
     *
     * @return $this
     */
    public function setCertificate($certificate)
    {
        $this->certificate = $certificate;

        return $this;
    }

    /**
     * @return string
     */
    public function getCsr()
    {
        return $this->csr;
    }

    /**
     * @return string
     */
    public function getCertificate()
    {
        return $this->certificate;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

}