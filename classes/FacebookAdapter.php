<?php

namespace OAuth\Plugin;



use OAuth\OAuth2\Service\Facebook;

class FacebookAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request('/me?fields=name,email'));

        if( !empty($result['username']) )
        {
            $data['user'] = $result['username'];
        }
        else
        {
            $data['user'] = $result['name'];
        }
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(Facebook::SCOPE_EMAIL);
    }

}
