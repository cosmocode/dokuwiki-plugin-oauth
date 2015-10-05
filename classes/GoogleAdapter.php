<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Google;

class GoogleAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request('https://www.googleapis.com/oauth2/v1/userinfo'));

        $data['user'] = $result['name'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }

    public function getAuthorizationUri() {
        $param = array();
        if ($this->hlp->getConf("google-hosted-domain") !== "") {
            $param = array("hd" => $this->hlp->getConf("google-hosted-domain"),);
        }
        return $this->oAuth->getAuthorizationUri($param);
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(Google::SCOPE_USERINFO_EMAIL, Google::SCOPE_USERINFO_PROFILE);
    }

    public function checkToken() {
        $tokenCheck = parent::checkToken();
        $hostedDomain = $this->hlp->getConf("google-hosted-domain");
        if ($tokenCheck && $hostedDomain !== '') {
            $userData = $this->getUser();
            if (substr($userData['mail'], -strlen($hostedDomain)) === $hostedDomain) {
                return true;
            }
            return false;
        }
        return $tokenCheck;
    }

}
