<?php

namespace OAuth\Plugin;

use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Class oAuthHTTPClient
 *
 * Implements the client interface using DokuWiki's HTTPClient
 */
class oAuthHTTPClient implements ClientInterface {

    /**
     * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
     * They should return, in string form, the response body and throw an exception on error.
     *
     * @param UriInterface $endpoint
     * @param mixed        $requestBody
     * @param array        $extraHeaders
     * @param string       $method
     *
     * @return string
     *
     * @throws TokenResponseException
     */
    public function retrieveResponse(
        UriInterface $endpoint,
        $requestBody,
        array $extraHeaders = array(),
        $method = 'POST'
    ) {
        $http = new \DokuHTTPClient();
        $http->headers = array_merge($http->headers, $extraHeaders);

        $ok = $http->sendRequest($endpoint->getAbsoluteUri(), $requestBody, $method);
        if(!$ok){
            $msg = "An error occured during the request to the oauth provider:\n";
            throw new TokenResponseException($msg . $http->error);
        }

        return $http->resp_body;
    }
}
