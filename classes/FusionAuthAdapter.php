<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\FusionAuth;

class FusionAuthAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'email', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $response = $this->oAuth->request('/oauth2/userinfo');
        $result = $JSON->decode($response);
	
        if( !empty($result['preferred_username']) )
        {
            $data['user'] = $result['preferred_username'];
        }
        else
        {
            $data['user'] = isset($result['preferred_username']) ? $result['preferred_username'] : $result['email'];
        }
        $data['name'] = isset($result['preferred_username']) ? $result['preferred_username'] : $result['email'];
        $data['mail'] = $result['email'];
	
        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(FusionAuth::SCOPE_OPENID);
    }

}
