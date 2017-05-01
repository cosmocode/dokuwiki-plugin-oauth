<?php

namespace OAuth\OAuth2\Service;

class WildApricot extends Generic
{
    const SCOPE_CONTACTS_ME='contacts_me';
    const ACTIVE_STATUSES=array('Active', 'PendingRenewal', 'PendingUpgrade');

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = array(
            'code'          => $code,
            'client_id'     => $this->credentials->getConsumerId(),
            'redirect_uri'  => $this->credentials->getCallbackUrl(),
            'grant_type'    => 'authorization_code',
            'scope'         => implode($this->scopes),
        );

        error_log("uri ".$this->getAccessTokenEndpoint());
        error_log("body params ".json_encode($bodyParams));
        error_log("extra headers ".json_encode($this->getExtraOAuthHeaders));
        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    protected function getExtraOAuthHeaders() {
        $authHeader='Basic '.base64_encode($plaintextHeader=$this->credentials->getConsumerId().':'.$this->credentials->getConsumerSecret());

        $headers=array(
            'ContentType'	=>	'application/x-www-form-urlencoded',
            'Authorization'	=>	$authHeader
        );
        return $headers;
    }

    protected function getExtraApiHeaders() {
        return array(
            'Content-Type'	=>	'application/json',
            'Accept'	=>	'application/json',
        );
    }

    /**
     * {@inheriteddoc}
     */
    public function needsStateParameterInAuthUrl() {
        return true;
    }
}
