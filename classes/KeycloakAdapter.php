<?php

namespace OAuth\Plugin;

/**
 * Class KeycloakAdapter
 *
 * This is a very rudimentary implementation of a keycloak adapter. mainly copied from the doorkeeper example
 *
 *
 * @link https://github.com/keycloak/keyloak
 * @package OAuth\Plugin
 */
class KeycloakAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps' and 'roles'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        /** var OAuth\OAuth2\Service\Generic $this->oAuth */
        $result = $JSON->decode($this->oAuth->request($this->hlp->getUserInfoEndpoint('Keycloak')));

        $data['user'] = $result['preferred_username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        if( !empty($result['groups']) )
        {
            $data['grps'] = $result['groups'];
        }
        $data['grps'] = $result['groups'];

        $data['roles'] = $result['roles'];

        return $data;
    }

    /**
     * Extend authorization checking by checking if the user has the requested role.
     * Does nothing, if the keycloak-required-role config option is not set
     *
     * @return bool
     */
    public function checkToken() {
        $res = parent::checkToken();
        if (!$res) return $res;

        $requiredRole = $this->hlp->getRequiredRole('Keycloak');
        if (!empty($requiredRole))
        {
            $userData = $this->getUser();
            if (empty($userData['roles']))
            {
                return false;
            }
            return in_array($requiredRole, $userData['roles'])
        }
        return $res;
    }

    /**
     * We make use of the Keycloak oauth2 service (slightly abstracted from "Generic") as defined in
     * phpoauthlib/src/OAuth/OAuth2/Service/Keycloak.php
     *
     * @return string
     */
    public function getServiceName() {
        return 'Keycloak';
    }

}
