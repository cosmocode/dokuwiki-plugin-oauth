<?php

namespace dokuwiki\plugin\oauth;

use dokuwiki\HTTP\DokuHTTPClient;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Implements the client interface using DokuWiki's HTTPClient
 */
class HTTPClient implements ClientInterface
{
    /** @inheritDoc */
    public function retrieveResponse(
        UriInterface $endpoint,
        $requestBody,
        array $extraHeaders = [],
        $method = 'POST'
    ) {
        $http = new DokuHTTPClient();
        $http->keep_alive = false;
        $http->headers = array_merge($http->headers, $extraHeaders);

        $ok = $http->sendRequest($endpoint->getAbsoluteUri(), $requestBody, $method);
        if (!$ok || $http->status < 200 || $http->status > 299) {
            $msg = "An error occured during the request to the oauth provider:\n";
            throw new TokenResponseException($msg . $http->error . ' [HTTP ' . $http->status . ']');
        }

        return $http->resp_body;
    }
}
