<?php

namespace OAuth\Plugin;

use OAuth\Common\Consumer\Credentials;
use OAuth\ServiceFactory;
use OAuth\Common\Http\Uri\Uri;

class GitlabAdapter extends AbstractAdapter {
    
    protected $gitlabUserData = null;
    
    protected $gitlabUserApiData = [];
    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'email', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        
        $data = array();

        $result = $this->getGitlabUserData();
        $data['user'] = $result['username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }
    
    protected function getGitlabUserData() {
        if (null !== $this->gitlabUserData) {
            return $this->gitlabUserData;
        }
        
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $this->gitlabUserData = $JSON->decode($this->oAuth->request('user'));
        
        return $this->gitlabUserData;
    }
    
    protected function getGitlabUserGroups() {
        if (isset($this->gitlabUserApiData['group'])) {
            return $this->gitlabUserApiData['group'];
        }
        
        $groups = [];
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        foreach($JSON->decode($this->oAuth->request('groups')) as $group) {
            $groups[$group['path']] = $group;
        }
        
        $this->gitlabUserApiData['group'] = $groups;
        
        return $groups;
    }
    
    protected function getGitlabUserProjects() {
        if (isset($this->gitlabUserApiData['projects'])) {
            return $this->gitlabUserApiData['projects'];
        }
        
        $projects = [];
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        foreach($JSON->decode($this->oAuth->request('projects')) as $project) {
            $projects[$project['path']] = $project;
        }
        
        $this->gitlabUserApiData['projects'] = $projects;
        
        return $groups;
    }
    

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array('read_user');
    }
    
    public function checkMatchRules() {
        
        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauth');
        
        if (!$rules = trim($hlp->getConf('gitlab-rules'))) {
            return true;
        }
        
        $rules = explode("\n", $rules);
        
        $namespacedDataFunctions = [
            'user' => [$this, getGitlabUserData],
            'groups' => [$this, 'getGitlabUserGroups'],
            'projects' => [$this, 'getGitlabUserProjects'],
        ];
        
        foreach ($rules as $rule) {
            $rule = trim($rule);
            if (!$rule || substr($rule, 0, 1) === '#') {
                continue;
            }
            
            // ns/key/subkey/subsubkey.. [ (!=|=) value ]
            if (!preg_match('#^\s*([a-z-_]+)/([a-z-_/]+)\s*(?:(!?=)\s*(.+))?$#i', $rule, $match)) {
                dbglog('Wrong gitlab rule format '.$rule.'. Ignoring.');
                continue;
            }
            
            $ns = $match[1];
            if (!isset($namespacedDataFunctions[$ns])) {
                dbglog('Unknow gitlab rule namespace '.$ns.' in rule "'.$rule.'". Ignoring.');
                continue;
            }
            
            $nsData = call_user_func($namespacedDataFunctions[$ns]);
            $fullKey = $match[2];
            $existOnly = empty($match[3]);
            
            $targetValue = $nsData;
            foreach (explode('/', $fullKey) as $key) {
                if ('' === $key) {
                    return $targetValue;
                }
                
                if (array_key_exists($key, $targetValue)) {
                    $targetValue = $targetValue[$key];
                } else {
                    $targetValue = null;
                    break;
                }
            }
            
            if (!$existOnly) {
                $isNot = ($match[3] == '!='); // else equal to "="
                $value = $match[4];
                $ruleCheck = ( ($targetValue == $value) xor $isNot );
            } else {
                $ruleCheck = null !== $targetValue;
            }
            
            if (!$ruleCheck) {
                //dbglog('User does not validate rule "'.$rule.'"');
                return false;
            }
        }
        
        return true;
    }
    
    public function checkToken() {
        if (!parent::checkToken()) {
            return false;
        }
        
        return $this->checkMatchRules();
    }

}
