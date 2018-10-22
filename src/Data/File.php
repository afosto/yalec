<?php

namespace Afosto\LetsEncrypt\Data;

class File
{

    /**
     * @var string
     */
    protected $filename;

    /**
     * @var string
     */
    protected $contents;

    /**
     * @param $filename
     *
     * @return $this
     */
    public function setFilename($filename)
    {
        $this->filename = $filename;

        return $this;
    }

    /**
     * @param $contents
     *
     * @return $this
     */
    public function setContents($contents)
    {
        $this->contents = $contents;

        return $this;
    }

    /**
     * @return string
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * @return string
     */
    public function getContents()
    {
        return $this->contents;
    }
}
