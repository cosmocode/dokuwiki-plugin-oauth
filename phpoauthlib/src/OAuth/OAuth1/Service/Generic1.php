<?php

namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\OAuth1\Service\Exception\InvalidServiceConfigurationException;
use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;


class Generic1 extends AbstractService
{

    protected $requestTokenEndpoint = null;

    protected $authorizationEndpoint = null;

    protected $accessTokenEndpoint = null;

    protected $baseApiUri = null;

    /**
     * Set the API endpoint.
     *
     * has to be called before using the service
     *
     * @param $url
     */
    public function setApiEndpoint($url)
    {
        $this->baseApiUri = new Uri($url);
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenEndpoint()
    {
        if(is_null($this->requestTokenEndpoint)) {
            throw new InvalidServiceConfigurationException('No RequestTokenEndpoint set');
        }
        return $this->requestTokenEndpoint;
    }

    /**
     * Set the request token endpoint.
     *
     * has to be called before using the service
     *
     * @param $url
     */
    public function setRequestTokenEndpoint($url)
    {
        $this->requestTokenEndpoint = new Uri($url);
    }

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
    protected function parseRequestTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['oauth_problem'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['oauth_problem'] . '"');
        } elseif (!isset($data['oauth_callback_confirmed']) || $data['oauth_callback_confirmed'] !== 'true') {
            throw new TokenResponseException('Error in retrieving token.');
        }

        return $this->parseAccessTokenResponse($responseBody);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth1Token();

        $token->setRequestToken($data['oauth_token']);
        $token->setRequestTokenSecret($data['oauth_token_secret']);
        $token->setAccessToken($data['oauth_token']);
        $token->setAccessTokenSecret($data['oauth_token_secret']);

        $token->setEndOfLife(StdOAuth1Token::EOL_NEVER_EXPIRES);
        unset($data['oauth_token'], $data['oauth_token_secret']);
        $token->setExtraParams($data);

        return $token;
    }
}
