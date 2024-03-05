<?php

namespace dokuwiki\plugin\oauth\Service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\OAuth2\Service\AbstractService;
use OAuth\OAuth2\Token\StdOAuth2Token;

/**
 * Implements the parseAccessTokenResponse like most services do it. Can be used as a base
 * for custom services.
 */
abstract class AbstractOAuth2Base extends AbstractService
{
    /** @inheritdoc */
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
        unset($data['access_token']);

        if (isset($data['expires_in'])) {
            $token->setLifeTime($data['expires_in']);
            unset($data['expires_in']);
        } else {
            $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * We accept arbitrary scopes
     *
     * @param string $scope
     * @return bool
     */
    public function isValidScope($scope)
    {
        return true;
    }
}
