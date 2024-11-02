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
    protected $httpRespBody = "";

    /**
     * @param string $message
     * @param int $httpStatusCode
     * @param string httpErrorMessage
     * @param mixed httpRespBody
     * @param int $code
     * @param \Throwable|null $previous
     */
    public function __construct(
        $message = "",
        $httpStatusCode = 0,
        $httpErrorMessage = "",
        $httpRespBody = "",
        $code = 0,
        \Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->httpStatusCode = $httpStatusCode;
        $this->httpErrorMessage = $httpErrorMessage;
        $this->httpRespBody = $httpRespBody;
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

    /**
     * Get the HTTP response body
     *
     * @return mixed
     */
    public function getHttpRespBody()
    {
        return $this->httpRespBody;
    }
}
