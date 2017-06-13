<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\GitHub;

class GithubAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request('user'));
        $data['user'] = $result['login'];
        $data['name'] = $result['name'];

        $result = $JSON->decode($this->oAuth->request('user/emails'));
        foreach($result as $row) {
            if($row['primary']){
                $data['mail'] = $row['email'];
                break;
            }
        }

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(GitHub::SCOPE_USER_EMAIL);
    }

}
