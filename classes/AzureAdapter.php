<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Azure;

/**
 * Class AzureAdapter
 *
 */
class AzureAdapter extends AbstractAdapter
{

    /**
     * Redirects to the service for requesting access
     * This is the first step of oAuth authentication
     */
    public function login()
    {
        $url = $this->oAuth->getAuthorizationUri(['resource' => 'https://graph.windows.net/']);
        send_redirect($url);
    }

    protected function getGroupMap($mapping)
    {
        $result = array();

        if ($mapping !== '') {
            $lines = explode("\n", $mapping);

            foreach ($lines as $line) {
                list($key, $val) = explode('=', $line);
                $result[$key] = $val;
            }
        }

        return $result;
    }

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser()
    {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $result = $this->oAuth->request('https://graph.windows.net/me?api-version=1.6');
        $result = $JSON->decode($result);

        $data['user'] = $result['userPrincipalName'];
        $data['name'] = $result['displayName'];
        $data['mail'] = $result['mail'];

        $grpmap = $this->hlp->getConf('azure-groupmapping');

        if (trim($grpmap) != '') {
            $body = '{ "securityEnabledOnly": true }';
            $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json'];
            $result = $this->oAuth->request('https://graph.windows.net/me/getMemberGroups?api-version=1.6',
                'POST', $body, $headers);
            $result = $JSON->decode($result);

            $mapping = $this->getGroupMap($grpmap);
            $data['grps'] = array();

            foreach ($result['value'] as $group_id) {
                if (array_key_exists($group_id, $mapping)) {
                    array_push($data['grps'], $mapping[$group_id]);
                }
            }
        }

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope()
    {
        return array(Azure::SCOPE_SIGNIN_READ_PROFILE);
    }
}
