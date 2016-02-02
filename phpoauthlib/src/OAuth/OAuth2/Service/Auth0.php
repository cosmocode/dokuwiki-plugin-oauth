<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Exception\Exception;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Auth0 extends AbstractService
{

    const SCOPE_OPENID = 'openid';
    protected $domain;

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        $hlp = plugin_load('helper', 'oauth');
        $this->domain = $hlp->getConf('auth0-domain');

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri("https://{$this->domain}/");
        }
    }

    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri("https://{$this->domain}/authorize/");
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri("https://{$this->domain}/oauth/token/");
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = $JSON->decode($responseBody);

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

    public function getDialogUri($dialogPath, array $parameters)
    {
        if (!isset($parameters['redirect_uri'])) {
            throw new Exception("Redirect uri is mandatory for this request");
        }

        $parameters['client_id'] = $this->credentials->getConsumerId();
        $baseUrl = "https://{$this->domain}/authorize/";
        $query = http_build_query($parameters);
        return new Uri($baseUrl . '?' . $query);
    }
}
