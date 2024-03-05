<?php

namespace dokuwiki\plugin\oauth;

/**
 * Our own OAuth Plugin Exceptions
 *
 * @todo maybe add debug logging here later
 * @todo add translations here
 */
class Exception extends \OAuth\Common\Exception\Exception
{
    protected $context = [];

    /**
     * @param string $message
     * @param array $context
     * @param int $code
     * @param \Throwable|null $previous
     */
    public function __construct($message = "", $context = [], $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /**
     * Get the translation context
     *
     * @return array
     */
    public function getContext()
    {
        return $this->context;
    }

    /**
     * Set the translation context
     *
     * @param array $context
     */
    public function setContext(array $context)
    {
        $this->context = $context;
    }
}
