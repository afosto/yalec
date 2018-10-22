<?php

namespace Afosto\LetsEncrypt\Data;


use Afosto\LetsEncrypt\Client;

class Authorization
{

    /**
     * @var Identifier
     */
    protected $identifier;

    /**
     * @var \DateTime
     */
    protected $expires;

    /**
     * @var Challenge[]
     */
    protected $challenges = [];

    /**
     * @var string
     */
    protected $thumbprint;

    /**
     * Authorization constructor.
     *
     * @param $thumbprint
     */
    public function __construct($thumbprint)
    {
        $this->thumbprint = $thumbprint;
    }

    /**
     * @param $type
     * @param $value
     *
     * @return $this
     */
    public function setIdentifier($type, $value)
    {
        $this->identifier = new Identifier();
        $this->identifier->setType($type)->setValue($value);

        return $this;
    }

    /**
     * @return Identifier
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * @param \DateTime $expires
     *
     * @return $this
     */
    public function setExpires(\DateTime $expires)
    {
        $this->expires = $expires;

        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * @param $type
     * @param $status
     * @param $token
     * @param $uri
     *
     * @return $this
     */
    public function addChallenge($type, $status, $token, $uri)
    {
        $challenge = new Challenge();
        $challenge->setType($type)->setStatus($status)->setToken($token)->setUri($uri);
        $this->challenges[] = $challenge;

        return $this;
    }

    /**
     * @return Challenge[]
     */
    public function getChallenges()
    {
        return $this->challenges;
    }

    /**
     * @return File|bool
     */
    public function getFile()
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_HTTP) {
                $file = new File();
                $file->setFilename($challenge->getToken());
                $file->setContents($challenge->getToken() . '.' . $this->thumbprint);

                return $file;
            }
        }

        return false;
    }
}
