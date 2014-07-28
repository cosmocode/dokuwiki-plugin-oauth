<?php

namespace OAuth\Plugin;


class DoorkeeperAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $result = $JSON->decode($this->oAuth->request('https://doorkeeper-provider.herokuapp.com/api/v1/me.json'));

        $data['user'] = 'doorkeeper-'.$result['id'];
        //$data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }

    public function getServiceName() {
        return 'Generic';
    }

}