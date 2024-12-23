<?php

namespace dokuwiki\plugin\oauth;

use dokuwiki\Logger;

/**
 * Implements the flow control for oAuth
 */
class OAuthManager
{
    // region main flow

    /**
     * Explicitly starts the oauth flow by redirecting to IDP
     *
     * @throws \OAuth\Common\Exception\Exception
     */
    public function startFlow($servicename)
    {
        global $ID;

        $session = Session::getInstance();
        $session->setLoginData($servicename, $ID);

        $service = $this->loadService($servicename);
        $service->initOAuthService();
        $service->login(); // redirects
    }

    /**
     * Continues the flow from various states
     *
     * @return bool true if the login has been handled
     * @throws Exception
     * @throws \OAuth\Common\Exception\Exception
     */
    public function continueFlow()
    {
        return $this->loginByService() || $this->loginBySession() || $this->loginByCookie();
    }

    /**
     * Second step in a explicit login, validates the oauth code
     *
     * @return bool true if successful, false if not applies
     * @throws \OAuth\Common\Exception\Exception
     */
    protected function loginByService()
    {
        global $INPUT;

        if (!$INPUT->get->has('code') && !$INPUT->get->has('oauth_token')) {
            return false;
        }

        $session = Session::getInstance();

        // init service from session
        $logindata = $session->getLoginData();
        if (!$logindata) return false;
        $service = $this->loadService($logindata['servicename']);
        $service->initOAuthService();

        $session->clearLoginData();

        // oAuth login
        if (!$service->checkToken()) throw new \OAuth\Common\Exception\Exception("Invalid Token - Login failed");
        $userdata = $service->getUser();

        // processing
        $userdata = $this->validateUserData($userdata, $logindata['servicename']);
        $userdata = $this->processUserData($userdata, $logindata['servicename']);

        // store data
        $storageId = $this->getStorageId($userdata['mail']);
        $service->upgradeStorage($storageId);

        // login
        $session->setUser($userdata); // log in
        $session->setCookie($logindata['servicename'], $storageId); // set cookie

        // redirect to the appropriate ID
        if (!empty($logindata['id'])) {
            send_redirect(wl($logindata['id'], [], true, '&'));
        }
        return true;
    }

    /**
     * Login based on user's current session data
     *
     * This will also log in plainauth users
     *
     * @return bool true if successful, false if not applies
     * @throws Exception
     */
    protected function loginBySession()
    {
        $session = Session::getInstance();
        if (!$session->isValid()) {
            $session->clear();
            return false;
        }

        $userdata = $session->getUser();
        if (!$userdata) return false;
        if (!isset($userdata['user'])) return false; // default dokuwiki does not put username here, let DW handle it
        $session->setUser($userdata, false); // does a login without resetting the time
        return true;
    }

    /**
     * Login based on user cookie and a previously saved access token
     *
     * @return bool true if successful, false if not applies
     * @throws \OAuth\Common\Exception\Exception
     */
    protected function loginByCookie()
    {
        $session = Session::getInstance();
        $cookie = $session->getCookie();
        if (!$cookie) return false;

        $service = $this->loadService($cookie['servicename']);
        $service->initOAuthService($cookie['storageId']);

        // ensure that we have a current access token
        $service->refreshOutdatedToken();

        // this should use a previously saved token
        $userdata = $service->getUser();

        // processing
        $userdata = $this->validateUserData($userdata, $cookie['servicename']);
        $userdata = $this->processUserData($userdata, $cookie['servicename']);

        $session->setUser($userdata); // log in
        return true;
    }

    /**
     * Callback service's logout
     *
     * @return void
     */
    public function logout()
    {
        $session = Session::getInstance();
        $cookie = $session->getCookie();
        if (!$cookie) return;
        try {
            $service = $this->loadService($cookie['servicename']);
            $service->initOAuthService($cookie['storageId']);
            $service->logout();
        } catch (\OAuth\Common\Exception\Exception $e) {
            return;
        }
    }

    // endregion

    /**
     * The ID we store authentication data as
     *
     * @param string $mail
     * @return string
     */
    protected function getStorageId($mail)
    {
        return md5($mail);
    }

    /**
     * Clean and validate the user data provided from the service
     *
     * @param array $userdata
     * @param string $servicename
     * @return array
     * @throws Exception
     */
    protected function validateUserData($userdata, $servicename)
    {
        /** @var \auth_plugin_oauth */
        global $auth;

        // mail is required
        if (empty($userdata['mail'])) {
            throw new Exception('noEmail', [$servicename]);
        }

        $userdata['mail'] = strtolower($userdata['mail']);

        // mail needs to be allowed
        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        if (!$hlp->checkMail($userdata['mail'])) {
            throw new Exception('rejectedEMail', [implode(', ', $hlp->getValidDomains())]);
        }

        // make username from mail if empty
        if (!isset($userdata['user'])) $userdata['user'] = '';
        $userdata['user'] = $auth->cleanUser((string)$userdata['user']);
        if ($userdata['user'] === '') {
            [$userdata['user']] = explode('@', $userdata['mail']);
        }

        // make full name from username if empty
        if (empty($userdata['name'])) {
            $userdata['name'] = $userdata['user'];
        }

        // make sure groups are array and valid
        if (!isset($userdata['grps'])) $userdata['grps'] = [];
        $userdata['grps'] = array_map([$auth, 'cleanGroup'], (array)$userdata['grps']);

        return $userdata;
    }

    /**
     * Process the userdata, update the user info array and create the user if necessary
     *
     * Uses the global $auth object for user management
     *
     * @param array $userdata User info received from authentication
     * @param string $servicename Auth service
     * @return array the modified user info
     * @throws Exception
     */
    protected function processUserData($userdata, $servicename)
    {
        /** @var \auth_plugin_oauth $auth */
        global $auth;

        // see if the user is known already
        $localUser = $auth->getUserByEmail($userdata['mail']);
        if ($localUser) {
            $localUserInfo = $auth->getUserData($localUser);
            $localUserInfo['user'] = $localUser;
            if (isset($localUserInfo['pass'])) unset($localUserInfo['pass']);

            // check if the user allowed access via this service
            if (!in_array($auth->cleanGroup($servicename), $localUserInfo['grps'])) {
                throw new Exception('authnotenabled', [$servicename]);
            }

            $helper = plugin_load('helper', 'oauth');

            $userdata['user'] = $localUser;
            $userdata['name'] = $localUserInfo['name'];
            $userdata['grps'] = $this->mergeGroups(
                $localUserInfo['grps'],
                $userdata['grps'] ?? [],
                array_keys($helper->listServices(false)),
                $auth->getOption('overwrite-groups')
            );

            // update user if changed
            sort($localUserInfo['grps']);
            sort($userdata['grps']);
            if ($localUserInfo != $userdata && !isset($localUserInfo['protected'])) {
                $auth->modifyUser($localUser, $userdata);
            }
        } elseif (actionOK('register') || $auth->getOption('register-on-auth')) {
            if (!$auth->registerOAuthUser($userdata, $servicename)) {
                throw new Exception('generic create error');
            }
        } else {
            throw new Exception('addUser not possible');
        }

        return $userdata;
    }

    /**
     * Merges local and provider user groups. Keeps internal
     * Dokuwiki groups unless configured to overwrite all ('overwrite-groups' setting)
     *
     * @param string[] $localGroups Local user groups
     * @param string[] $providerGroups Groups fetched from the provider
     * @param string[] $servicenames Service names that should be kept if set
     * @param bool $overwrite Config setting to overwrite local DokuWiki groups
     *
     * @return array
     */
    protected function mergeGroups($localGroups, $providerGroups, $servicenames, $overwrite)
    {
        global $conf;

        // overwrite-groups set in config - remove all local groups except services and default
        if ($overwrite) {
            $localGroups = array_intersect($localGroups, array_merge($servicenames, [$conf['defaultgroup']]));
        }

        return array_unique(array_merge($localGroups, $providerGroups));
    }

    /**
     * Instantiates a Service by name
     *
     * @param string $servicename
     * @return Adapter
     * @throws Exception
     */
    protected function loadService($servicename)
    {
        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        $srv = $hlp->loadService($servicename);

        if ($srv === null) throw new Exception("No such service $servicename");
        return $srv;
    }
}
