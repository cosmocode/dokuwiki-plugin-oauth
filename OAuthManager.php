<?php

namespace dokuwiki\plugin\oauth;

use OAuth\Common\Http\Exception\TokenResponseException;

class OAuthManager
{

    /**
     * @throws Exception
     * @throws TokenResponseException
     */
    public function startFlow($servicename)
    {
        // generate a new GUID to identify this user
        $guid = bin2hex(random_bytes(16));

        $session = Session::getInstance();
        $session->setLoginData($servicename, $guid);

        // fixme store environment
        $service = $this->loadService($servicename);
        $service->initOAuthService($guid);
        $service->login(); // redirects

    }

    /**
     * @return bool true if the login has been handled
     * @throws Exception
     * @throws \OAuth\Common\Exception\Exception
     * @todo this probably moves over to auth
     */
    public function continueFlow()
    {

        return $this->loginByService() or
            $this->loginBySession() or
            $this->loginByCookie();

    }

    /**
     * @return bool true if successful, false if not applies,
     * @throws \OAuth\Common\Exception\Exception
     * @throws Exception
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
        $service->initOAuthService($logindata['guid']);
        $session->clearLoginData();

        // oAuth login
        if (!$service->checkToken()) throw new Exception("Login failed");
        $userdata = $service->getUser();

        // processing
        $userdata = $this->validateUserData($userdata, $logindata['servicename']);
        $userdata = $this->processUserData($userdata, $logindata['servicename']);

        // login
        $session->setUser($userdata); // log in
        $session->setCookie($logindata['servicename'], $logindata['guid']); // set cookie

        // fixme restore environment

        return true;
    }

    /**
     * Login a user based on their current session data
     *
     * This will also log in plainauth users
     *
     * @return bool true if successful, false if not applies,
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
        $session->setUser($userdata, false); // does a login without resetting the time

        return true;
    }

    /**
     * Login a user based on their cookie and a previously saved access token
     *
     * @return bool true if successful, false if not applies,
     * @throws Exception
     */
    protected function loginByCookie()
    {
        $session = Session::getInstance();
        $cookie = $session->getCookie();
        if (!$cookie) return false;

        try {
            $service = $this->loadService($cookie['servicename']);
            $service->initOAuthService($cookie['guid']);
        } catch (Exception $e) {
            return false; // maybe cookie had old service that is no longer available
        }

        $userdata = $service->getUser(); // this should use a previously saved token
        $session->setUser($userdata); // log in
        return true;
    }

    /**
     * Clean and validate the user data provided from the service
     *
     * @param array $userdata
     * @param string $servicename
     * @return array
     * @throws Exception
     * @todo test
     */
    protected function validateUserData($userdata, $servicename)
    {
        /** @var \auth_plugin_oauth */
        global $auth;

        // mail is required
        if (empty($userdata['mail'])) {
            throw new Exception("$servicename did not provide the an email address. Can't log you in");
        }

        // mail needs to be allowed
        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        $hlp->checkMail($userdata['mail']);

        // make username from mail if empty
        $userdata['user'] = $auth->cleanUser((string)$userdata['user']);
        if ($userdata === '') {
            list($userdata['user']) = explode('@', $userdata['mail']);
        }

        // make full name from username if empty
        if (empty($userdata['name'])) {
            $userdata['name'] = $userdata['user'];
        }

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
        /** @var \auth_plugin_oauth */
        global $auth;

        // see if the user is known already
        $localUser = $auth->getUserByEmail($userdata['mail']);
        if ($localUser) {
            $localUserInfo = $auth->getUserData($localUser);
            // check if the user allowed access via this service
            if (!in_array($auth->cleanGroup($servicename), $localUserInfo['grps'])) {
                throw new Exception(sprintf($auth->getLang('authnotenabled'), $servicename));
            }
            $userdata['user'] = $localUser;
            $userdata['name'] = $localUserInfo['name'];
            $userdata['grps'] = array_merge((array)$userdata['grps'], $localUserInfo['grps']);
        } elseif (actionOK('register') || $auth->getConf('register-on-auth')) {
            if (!$auth->addUser($userdata, $servicename)) {
                throw new Exception('something went wrong creating your user account. please try again later.');
            }
        } else {
            throw new Exception($auth->getLang('addUser not possible'));
        }

        return $userdata;
    }

    /**
     * Instantiates a Service by name
     *
     * @param string $servicename
     * @return Service
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
