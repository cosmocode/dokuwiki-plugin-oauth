<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Service\Exception\InvalidServiceConfigurationException;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Generic extends AbstractService
{

    protected $authorizationEndpoint = null;

    protected $accessTokenEndpoint = null;

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        if(is_null($this->authorizationEndpoint)) {
            throw new InvalidServiceConfigurationException('No AuthorizationEndpoint set');
        }
        return $this->authorizationEndpoint;
    }

    /**
     * Set the authorization endpoint.
     *
     * has to be called before using the service
     *
     * @param $url
     */
    public function setAuthorizationEndpoint($url)
    {
        $this->authorizationEndpoint = new Uri($url);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        if(is_null($this->accessTokenEndpoint)) {
            throw new InvalidServiceConfigurationException('No AccessTokenEndpoint set');
        }
        return $this->accessTokenEndpoint;
    }

    /**
     * Set the access token endpoint.
     *
     * has to be called before using the service
     *
     * @param $url
     */
    public function setAccessTokenEndpoint($url)
    {
        $this->accessTokenEndpoint = new Uri($url);
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires'])) {
            $token->setLifeTime($data['expires']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires']);

        $token->setExtraParams($data);

        return $token;
    }
}
