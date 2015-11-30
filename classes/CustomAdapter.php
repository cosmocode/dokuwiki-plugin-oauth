<?php

namespace OAuth\OAuth2\Service;
use OAuth\OAuth2\Service\Generic;

// custom provider that allows free setting of scope
class Custom extends Generic
{
  public function isValidScope($scope)
    {
        return true;
    }
  protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }
}

namespace OAuth\Plugin;

/**
 * Class DoorkeeperAdapter
 *
 * This is an example on how to implement your own adapter for making DokuWiki login against
 * a custom oAuth provider. The used Generic Service backend expects the authorization and
 * token endpoints to be configured in the DokuWiki backend.
 *
 * Your custom API to access user data has to be implemented in the getUser function. The one here
 * is setup to work with the demo setup of the "Doorkeeper" ruby gem.
 *
 * @link https://github.com/doorkeeper-gem/doorkeeper
 * @package OAuth\Plugin
 */
class CustomAdapter extends AbstractAdapter {

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

        $result = $JSON->decode($this->oAuth->request($this->hlp->conf['custom-meurl']));
        foreach(explode(" ", $this->hlp->conf['custom-mapping']) as $map) {
           $smap = explode("=", $map, 2);
           $data[$smap[0]] = $result[$smap[1]];
        }

        return $data;
    }

    /**
     * We make use of the "Generic" oAuth 2 Service as defined in
     * phpoauthlib/src/OAuth/OAuth2/Service/Generic.php
     *
     * @return string
     */
    public function getServiceName() {
        // the custom class we defined
        return 'Custom';
    }

    /**
     * Return the scope to request
     *
     * This should return the minimal scope needed for accessing the user's data
     *
     * @return array
     */
    public function getScope() {
        return explode(",", $this->hlp->conf['custom-scope']);
    }

}
