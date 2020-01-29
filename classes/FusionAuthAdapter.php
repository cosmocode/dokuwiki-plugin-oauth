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
	
        if( !empty($result['username']) )
        {
            $data['user'] = $result['username'];
        }
        else
        {
            $data['user'] = isset($result['name']) ? $result['name'] : $result['email'];
        }
        $data['name'] = isset($result['name']) ? $result['name'] : $result['email'];
        $data['mail'] = $result['email'];
	//error_log(json_encode($data));
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
