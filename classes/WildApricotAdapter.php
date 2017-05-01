<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\WildApricot;

/**
 * Class WildApricotAdapter
 *
 * The used Generic Service backend expects the authorization and token endpoints to be configured in the DokuWiki backend.
 *
 * @package OAuth\Plugin
 */
class WildApricotAdapter extends AbstractAdapter {

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

        /** var OAuth\OAuth2\Service\Generic $this->oAuth */
        $result = $JSON->decode($this->oAuth->request($this->hlp->getUserInfoEndpoint('WildApricot')));
        if (! in_array($result['Status'], WildApricot::ACTIVE_STATUSES)) {
            msg('Your account is not active', -1);
        } else {
            $data['user'] = 'wildapricot-'.$result['DisplayName'];
            $data['name'] = $result['FirstName'].' '.$result['LastName'];
            $data['mail'] = $result['Email'];
        }

        return $data;
    }

    /**
     * What service name do we use for the back end?
     *
     * @return string
     */
    public function getServiceName() {
        return 'WildApricot';
    }

    public function login() {
        $parameters = array();

        if(!empty($_SESSION[DOKU_COOKIE]['auth']['info']['mail'])) {
            $usermail = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
            $parameters['login_hint'] = $usermail;
        }

        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer', false, true);
        if ($farmer && $animal = $farmer->getAnimal()) {
            $parameters['state'] = urlencode(base64_encode(json_encode(array('animal'=>$animal,'state'=> md5(rand())))));
        } else {
            $parameters['state'] = urlencode(base64_encode(json_encode(array('state'=> md5(rand())))));
        }

        $this->storage->storeAuthorizationState('WildApricot', '');

        $url = $this->oAuth->getAuthorizationUri();

        send_redirect($url);
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(WildApricot::SCOPE_CONTACTS_ME);
    }

}
