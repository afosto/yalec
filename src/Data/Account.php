<?php

namespace Afosto\LetsEncrypt\Data;

class Account
{

    /**
     * @var string
     */
    protected $tos;

    /**
     * @var string
     */
    protected $accountReference;

    /**
     * @var bool
     */
    protected $hasAgreement = false;

    /**
     * @param $tos
     *
     * @return $this
     */
    public function setTos($tos)
    {
        $this->tos = $tos;

        return $this;
    }

    /**
     * @param $reference
     *
     * @return $this
     */
    public function setAccountReference($reference)
    {
        $this->accountReference = $reference;

        return $this;
    }

    /**
     * @return string
     */
    public function getTos()
    {
        return $this->tos;
    }

    /**
     * @return string
     */
    public function getAccountReference()
    {
        return $this->accountReference;
    }

    /**
     * @return bool
     */
    public function getHasAgreement()
    {
        return $this->hasAgreement;
    }

    /**
     * @param bool $status
     *
     * @return $this
     */
    public function setHasAgreement(bool $status = false)
    {
        $this->hasAgreement = (bool)$status;

        return $this;
    }
}
