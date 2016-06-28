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

        print_r($result);

        $data['user'] = $result['user']['userid'];
        $data['name'] = $result['user']['name'];
        $data['mail'] = $result['user']['email'];

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    //public function getScope() {
    //    return array(Dataporten::SCOPE_USERINFO_EMAIL, Dataporten::SCOPE_USERINFO_PROFILE);
    //}

    /*public function login() {
        $parameters = array(
            'grant_type' => 'code');
        //if(!empty($_SESSION[DOKU_COOKIE]['auth']['info']['mail'])) {
        //    $usermail = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
        //    $parameters['login_hint'] = $usermail;
        //}

        /** @var \helper_plugin_farmer $farmer 
        //$farmer = plugin_load('helper', 'farmer', false, true);
       
        $url = $this->oAuth->getAuthorizationUri($parameters);
        send_redirect($url);
    }*/

}
