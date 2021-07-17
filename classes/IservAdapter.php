<?php

namespace OAuth\Plugin;
use OAuth\OAuth2\Service\Iserv;


/**
 * Class IservAdapter
 *
 * This is an adapter for the iServ oAuth backend 
 *
 * @link https://iserv.de/doc/development/oauth/
 * @package OAuth\Plugin
 */
class IservAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request($this->baseApiUrl.'/iserv/public/oauth/userinfo'));

        $data['user'] = $result['preferred_username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];
        $data['grps'] = array();
        foreach($result['groups'] as $group){
           array_push($data['grps'], $group['act']);
        }
        return $data;
    }

     /**
     * Set scopes to access user information (Mail and Groups)
     *
     * @return array
     */
    public function getScope() {
        return array(ISERV::SCOPE_OPENID);
    }



    /**
     * We make use of the "Iserv" oAuth 2 Service as defined in
     * phpoauthlib/src/OAuth/OAuth2/Service/Iserv.php
     *
     * @return string
     */
    public function getServiceName() {
        return 'Iserv';
    }

}
