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
        $url = $this->oAuth->getAuthorizationUri(['resource' => 'https://graph.microsoft.com/']);
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
        
        // Updated to use Microsoft Graph API
        $result = $this->oAuth->request('https://graph.microsoft.com/v1.0/me');
        $result = $JSON->decode($result);
        
        $data['user'] = $result['userPrincipalName'];
        $data['name'] = $result['displayName'];
        $data['mail'] = $result['mail'] ? $result['mail'] : $result['userPrincipalName'];
        
        $grpmap = $this->hlp->getConf('azure-groupmapping');
        if (trim($grpmap) != '') {
            $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json'];
            
            // Using the memberOf endpoint to get group memberships instead of getMemberGroups
            $result = $this->oAuth->request(
                'https://graph.microsoft.com/v1.0/me/memberOf',
                'GET', null, $headers
            );
            
            $result = $JSON->decode($result);
            $mapping = $this->getGroupMap($grpmap);
            $data['grps'] = array();
            
            // Process groups from memberOf response format
            if (isset($result['value']) && is_array($result['value'])) {
                foreach ($result['value'] as $group) {
                    if (isset($group['id'])) {
                        $group_id = $group['id'];
                        if (array_key_exists($group_id, $mapping)) {
                            array_push($data['grps'], $mapping[$group_id]);
                        }
                    }
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
        // Updated scopes for Microsoft Graph API
        return array(
            'openid',
            'profile',
            'User.Read',
            'GroupMember.Read.All'
        );
    }
}
