<?php

namespace dokuwiki\plugin\oauth;

use OAuth\Common\Http\Exception\TokenResponseException;

/**
 * Exception relating to http token response from service.
 */
class HttpTokenResponseException extends TokenResponseException
{
    protected $httpStatusCode = 0;
    protected $httpErrorMessage = "";

    /**
     * @param string $message
     * @param int $httpStatusCode
     * @param string httpErrorMessage
     * @param int $code
     * @param \Throwable|null $previous
     */
    public function __construct(
        $message = "",
        $httpStatusCode = 0,
        $httpErrorMessage = "",
        $code = 0,
        \Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->httpStatusCode = $httpStatusCode;
        $this->httpErrorMessage = $httpErrorMessage;
    }

    /**
     * Get the HTTP status code
     *
     * @return int
     */
    public function getHttpStatusCode()
    {
        return $this->httpStatusCode;
    }

    /**
     * Get the HTTP error message
     *
     * @return string
     */
    public function getHttpErrorMessage()
    {
        return $this->httpErrorMessage;
    }
}
