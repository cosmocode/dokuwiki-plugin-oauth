<?php

use dokuwiki\plugin\oauth\SessionManager;

/**
 * DokuWiki Plugin oauth (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class auth_plugin_oauth extends auth_plugin_authplain
{

    /**
     * @var SessionManager
     */
    protected static $sessionManager;

    /** @inheritDoc */
    public function __construct()
    {
        parent::__construct();

        $this->cando['external'] = true;
        self::$sessionManager = SessionManager::getInstance();
    }

    /** @inheritDoc */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $INPUT;

        // handle redirects from farmer to animal wiki instances
        if ($INPUT->has('state') && plugin_load('helper', 'farmer', false, true)) {
            $this->handleFarmState($INPUT->str('state'));
        }

        // first check in auth setup: is auth data present and still valid?
        if ($this->sessionLogin()) return true;

        // if we have a service in session, either we're in oauth login or a previous login needs to be revalidated
        $servicename = self::$sessionManager->getServiceName();

        if ($servicename) {
            $pid = self::$sessionManager->getPid();
            $params = self::$sessionManager->getParams();
            $inProgress = self::$sessionManager->isInProgress();
            self::$sessionManager->setInProgress(false);
            self::$sessionManager->saveState();
            return $this->serviceLogin($servicename,
                $sticky,
                $pid,
                $params,
                $inProgress
            );
        }

        // otherwise try cookie
        $this->cookieLogin();

        // do the "normal" plain auth login via form
        return auth_login($user, $pass, $sticky);
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param null $grps
     * @return bool|null|string
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null)
    {
        if ($this->getUserByEmail($mail)) {
            msg($this->getLang('emailduplicate'), -1);
            return false;
        }

        return parent::createUser($user, $pwd, $name, $mail, $grps);
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @param string $user
     * @param array $changes
     * @return bool
     */
    public function modifyUser($user, $changes)
    {
        global $conf;

        if (isset($changes['mail'])) {
            $found = $this->getUserByEmail($changes['mail']);
            if ($found && $found != $user) {
                msg($this->getLang('emailduplicate'), -1);
                return false;
            }
        }

        $ok = parent::modifyUser($user, $changes);

        // refresh session cache
        touch($conf['cachedir'] . '/sessionpurge');

        return $ok;
    }

    /**
     * Unset additional stuff in session on logout
     */
    public function logOff()
    {
        parent::logOff();

        $this->cleanLogout();
    }

    /**
     * check if auth data is present in session and is still considered valid
     *
     * @return bool
     */
    protected function sessionLogin()
    {
        global $USERINFO;
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        // FIXME session can be null at this point (e.g. coming from sprintdoc svg.php)
        // FIXME and so the subsequent check for non-GET non-doku.php requests is not performed
        if (isset($session['oauth']) && $this->isSessionValid($session)) {
            $_SERVER['REMOTE_USER'] = $session['user'];
            $USERINFO = $session['info'];
            return true;
        }
        return false;
    }

    /**
     * Use cookie data to log in
     */
    protected function cookieLogin()
    {
        // FIXME SessionManager access?
        if (isset($_COOKIE[DOKU_COOKIE])) {
            list($cookieuser, $cookiesticky, $auth, $servicename) = explode('|', $_COOKIE[DOKU_COOKIE]);
            $auth = base64_decode($auth, true);
            $servicename = base64_decode($servicename, true);
            if ($auth === 'oauth') {
                $this->relogin($servicename);
            }
        }
    }

    /**
     * Use the OAuth service
     *
     * @param $servicename
     * @param $sticky
     * @param $page
     * @param $params
     * @param $existingLoginProcess
     * @return bool
     * @throws \OAuth\Common\Exception\Exception
     * @throws \OAuth\Common\Http\Exception\TokenResponseException
     * @throws \OAuth\Common\Storage\Exception\TokenNotFoundException
     */
    protected function serviceLogin($servicename, $sticky, $page, $params, $existingLoginProcess)
    {
        $service = $this->getService($servicename);
        if (is_null($service)) {
            $this->cleanLogout();
            return false;
        }

        if ($service->checkToken()) {
            if (!$this->processLogin($sticky, $service, $servicename, $page, $params)) {
                $this->cleanLogout();
                return false;
            }
            return true;
        } else {
            if ($existingLoginProcess) {
                msg($this->getLang('oauth login failed'), 0);
                $this->cleanLogout();
                return false;
            } else {
                // first time here
                $this->relogin($servicename);
            }
        }

        $this->cleanLogout();
        return false; // something went wrong during oAuth login
    }

    /**
     * Relogin using auth info read from session / cookie
     *
     * @param string $servicename
     * @return void|false
     * @throws \OAuth\Common\Http\Exception\TokenResponseException
     */
    protected function relogin($servicename)
    {
        $service = $this->getService($servicename);
        if (is_null($service)) return false;

        $this->writeSession($servicename);
        $service->login();
    }


    /**
     * @param bool $sticky
     * @param \dokuwiki\plugin\oauth\Service $service
     * @param string $servicename
     * @param string $page
     * @param array $params
     *
     * @return bool
     * @throws \OAuth\Common\Exception\Exception
     */
    protected function processLogin($sticky, $service, $servicename, $page, $params = [])
    {
        $userinfo = $service->getUser();
        $ok = $this->processUserinfo($userinfo, $servicename);
        if (!$ok) {
            return false;
        }
        $this->setUserSession($userinfo, $servicename);
        $this->setUserCookie($userinfo['user'], $sticky, $servicename);
        if (isset($page)) {
            if (!empty($params['id'])) unset($params['id']);
            send_redirect(wl($page, $params, false, '&'));
        }
        return true;
    }

    /**
     * process the user and update the user info array
     *
     * @param array $userinfo User info received from authentication
     * @param string $servicename Auth service
     *
     * @return bool
     */
    protected function processUserinfo(&$userinfo, $servicename)
    {
        $userinfo['user'] = $this->cleanUser((string)$userinfo['user']);
        if (!$userinfo['name']) $userinfo['name'] = $userinfo['user'];

        if (!$userinfo['user'] || !$userinfo['mail']) {
            msg("$servicename did not provide the needed user info. Can't log you in", -1);
            return false;
        }

        // see if the user is known already
        $localUser = $this->getUserByEmail($userinfo['mail']);
        if ($localUser) {
            $localUserInfo = $this->getUserData($localUser);
            // check if the user allowed access via this service
            if (!in_array($this->cleanGroup($servicename), $localUserInfo['grps'])) {
                msg(sprintf($this->getLang('authnotenabled'), $servicename), -1);
                return false;
            }
            $userinfo['user'] = $localUser;
            $userinfo['name'] = $localUserInfo['name'];
            $userinfo['grps'] = array_merge((array)$userinfo['grps'], $localUserInfo['grps']);
        } elseif (actionOK('register') || $this->getConf('register-on-auth')) {
            $ok = $this->addUser($userinfo, $servicename);
            if (!$ok) {
                msg('something went wrong creating your user account. please try again later.', -1);
                return false;
            }
        } else {
            msg($this->getLang('addUser not possible'), -1);
            return false;
        }
        return true;
    }

    /**
     * new user, create him - making sure the login is unique by adding a number if needed
     *
     * @param array $userinfo user info received from the oAuth service
     * @param string $servicename
     *
     * @return bool
     */
    protected function addUser(&$userinfo, $servicename)
    {
        global $conf;
        $user = $userinfo['user'];
        $count = '';
        while ($this->getUserData($user . $count)) {
            if ($count) {
                $count++;
            } else {
                $count = 1;
            }
        }
        $user = $user . $count;
        $userinfo['user'] = $user;
        $groups_on_creation = array();
        $groups_on_creation[] = $conf['defaultgroup'];
        $groups_on_creation[] = $this->cleanGroup($servicename); // add service as group
        $userinfo['grps'] = array_merge((array)$userinfo['grps'], $groups_on_creation);

        $ok = $this->triggerUserMod(
            'create',
            array($user, auth_pwgen($user), $userinfo['name'], $userinfo['mail'], $groups_on_creation,)
        );
        if (!$ok) {
            return false;
        }

        // send notification about the new user
        $subscription = new Subscription();
        $subscription->send_register($user, $userinfo['name'], $userinfo['mail']);
        return true;
    }

    /**
     * Find a user by email address
     *
     * @param $mail
     * @return bool|string
     */
    protected function getUserByEmail($mail)
    {
        if ($this->users === null) {
            if (is_callable([$this, '_loadUserData'])) {
                $this->_loadUserData();
            } else {
                $this->loadUserData();
            }
        }
        $mail = strtolower($mail);

        foreach ($this->users as $user => $userinfo) {
            if (strtolower($userinfo['mail']) == $mail) return $user;
        }

        return false;
    }

    /**
     * unset auth cookies and session information
     */
    private function cleanLogout()
    {
        if (isset($_SESSION[DOKU_COOKIE]['oauth-done'])) {
            unset($_SESSION[DOKU_COOKIE]['oauth-done']);
        }
        if (isset($_SESSION[DOKU_COOKIE]['auth'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']);
        }
        $this->setUserCookie('', true, '', -60);
    }

    /**
     * @param string $servicename
     * @return \dokuwiki\plugin\oauth\Service
     */
    protected function getService($servicename)
    {
        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        return $hlp->loadService($servicename);
    }


    /**
     * Save user and auth data
     *
     * @param array $data
     * @param string $service
     */
    protected function setUserSession($data, $service)
    {
        global $USERINFO;

        // set up groups
        if (!is_array($data['grps'])) {
            $data['grps'] = array();
        }
        $data['grps'][] = $this->cleanGroup($service);
        $data['grps'] = array_unique($data['grps']);

        $USERINFO = $data;
        $_SERVER['REMOTE_USER'] = $data['user'];


        // FIXME this is not handled by SessionManager because auth.php accesses the data directly
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $data['pass'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
        $_SESSION[DOKU_COOKIE]['auth']['time'] = time();
        $_SESSION[DOKU_COOKIE]['auth']['oauth'] = $service;
    }

    /**
     * @param string $user
     * @param bool $sticky
     * @param string $servicename
     * @param int $validityPeriodInSeconds optional, per default 1 Year
     */
    private function setUserCookie($user, $sticky, $servicename, $validityPeriodInSeconds = 31536000)
    {
        $cookie = base64_encode($user) . '|' . ((int)$sticky) . '|' . base64_encode('oauth') . '|' . base64_encode($servicename);
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        $time = $sticky ? (time() + $validityPeriodInSeconds) : 0;
        setcookie(DOKU_COOKIE, $cookie, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
    }

    /**
     * @param array $session cookie auth session
     *
     * @return bool
     */
    protected function isSessionValid($session)
    {
        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        if ($hlp->validBrowserID($session)) {
            if (!$hlp->isSessionTimedOut($session)) {
                return true;
            } elseif (!($hlp->isGETRequest() && $hlp->isDokuPHP())) {
                // only force a recheck on a timed-out session during a GET request on the main script doku.php
                return true;
            }
        }
        return false;
    }

    /**
     * Save login info in session
     *
     * @param string $servicename
     */
    protected function writeSession($servicename)
    {
        global $INPUT;

        // used to be in 'oauth-inprogress'
        self::$sessionManager->setServiceName($servicename);
        self::$sessionManager->setPid($INPUT->str('id'));
        self::$sessionManager->setParams($_GET);

        // used to be in 'oauth-done'
        self::$sessionManager->setRequest($_REQUEST);

        if (is_array($INPUT->post->param('do'))) {
            $doPost = key($INPUT->post->arr('do'));
        } else {
            $doPost = $INPUT->post->str('do');
        }
        $doGet = $INPUT->get->str('do');
        if (!empty($doPost)) {
            self::$sessionManager->setDo($doPost);
        } elseif (!empty($doGet)) {
            self::$sessionManager->setDo($doGet);
        }
        self::$sessionManager->saveState();
    }

    /**
     * Farmer plugin support
     *
     * When coming back to farmer instance via OAUTH redirectURI, we need to redirect again
     * to a proper animal instance detected from $state
     *
     * @param $state
     */
    private function handleFarmState($state)
    {
        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer', false, true);
        $data = json_decode(base64_decode(urldecode($state)));
        if (empty($data->animal) || $farmer->getAnimal() == $data->animal) {
            return;
        }
        $animal = $data->animal;
        $allAnimals = $farmer->getAllAnimals();
        if (!in_array($animal, $allAnimals)) {
            msg('Animal ' . $animal . ' does not exist!');
            return;
        }
        global $INPUT;
        $url = $farmer->getAnimalURL($animal) . '/doku.php?' . $INPUT->server->str('QUERY_STRING');
        send_redirect($url);
    }
}

// vim:ts=4:sw=4:et:
