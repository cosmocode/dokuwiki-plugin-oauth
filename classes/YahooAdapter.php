<?php

namespace OAuth\Plugin;

class YahooAdapter extends AbstractAdapter {

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

}