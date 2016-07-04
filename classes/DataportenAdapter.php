<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Dataporten;

class DataportenAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request('https://auth.dataporten.no/userinfo'));
        $groups = $JSON->decode($this->oAuth->request('https://groups-api.dataporten.no/groups/me/groups'));

        $user_groups = array();
        foreach($groups as $key) {
          array_push($user_groups, $key["id"]);
        }
        
        $data['user'] = $result['user']['userid'];
        $data['name'] = $result['user']['name'];
        $data['mail'] = $result['user']['email'];
        $data['grps'] = $user_groups;

        return $data;
    }

}
