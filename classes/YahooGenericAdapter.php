<?php

namespace OAuth\Plugin;

/**
 * This class have primary a pedagogical goal, as it fill the same role as the 
 * already existing YahooAdater class.
 */
class YahooGenericAdapter extends AbstractAdapter {

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

        $this->oAuth->setApiEndPoint('https://social.yahooapis.com/v1/'); 

        $result = $JSON->decode($this->oAuth->request('me/guid'));
        $guid   = $result['guid']['value'];

        $result = $JSON->decode($this->oAuth->request('users.guid('.$guid.')/profile'));

        foreach($result['profiles']['profile'][0]['emails'] as $email) {
            if(isset($email['primary'])) {
                $data['mail'] = $email['handle'];
                break;
            }
        }
        $data['name'] = trim($result['profiles']['profile'][0]['givenName'].' '.$result['profiles']['profile'][0]['familyName']);
        if(!$data['name']) $data['name'] = $result['profiles']['profile'][0]['nickname'];
        $data['user'] = $data['name'];

        return $data;
    }

    /**
     * We make use of the "Generic" oAuth 1 Service as defined in
     * phpoauthlib/src/OAuth/OAuth1/Service/Generic1.php
     *
     * @return string
     */
    public function getServiceName() {
        return 'Generic1';
    }
}