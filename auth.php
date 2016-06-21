<?php
/**
 * DokuWiki Plugin oauth (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_oauth extends auth_plugin_authplain {

    /**
     * Constructor
     *
     * Sets capabilities.
     */
    public function __construct() {
        parent::__construct();

        $this->cando['external'] = true;
    }

    private function handleState($state) {
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

    /**
     * Handle the login
     *
     * This either trusts the session data (if any), processes the second oAuth step or simply
     * executes a normal plugin against local users.
     *
     * @param string $user
     * @param string $pass
     * @param bool   $sticky
     * @return bool
     */
    function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO, $INPUT;

        if ($INPUT->has('state') && plugin_load('helper', 'farmer', false, true)) {
            $this->handleState($INPUT->str('state'));
        }

        // check session for existing oAuth login data
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        if(isset($session['oauth'])) {
            $servicename = $session['oauth'];
            // check if session data is still considered valid
            if ($this->isSessionValid($session)) {
                $_SERVER['REMOTE_USER'] = $session['user'];
                $USERINFO               = $session['info'];
                return true;
            }
        }

        $existingLoginProcess = false;
        // are we in login progress?
        if(isset($_SESSION[DOKU_COOKIE]['oauth-inprogress'])) {
            $servicename = $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'];
            $page        = $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id'];
            $params      = $_SESSION[DOKU_COOKIE]['oauth-inprogress']['params'];

            unset($_SESSION[DOKU_COOKIE]['oauth-inprogress']);
            $existingLoginProcess = true;
        }

        // either we're in oauth login or a previous log needs to be rechecked
        if(isset($servicename)) {
            /** @var helper_plugin_oauth $hlp */
            $hlp     = plugin_load('helper', 'oauth');

            /** @var OAuth\Plugin\AbstractAdapter $service */
            $service = $hlp->loadService($servicename);
            if(is_null($service)) {
                $this->cleanLogout();
                return false;
            }

            if($service->checkToken()) {
                $ok = $this->processLogin($sticky, $service, $servicename, $page, $params);
                if (!$ok) {
                    $this->cleanLogout();
                    return false;
                }
                return true;
            } else {
                if ($existingLoginProcess) {
                    msg($this->getLang('oauth login failed'),0);
                    $this->cleanLogout();
                    return false;
                } else {
                    // first time here
                    $this->relogin($servicename);
                }
            }

            $this->cleanLogout();
            return false; // something went wrong during oAuth login
        } elseif (isset($_COOKIE[DOKU_COOKIE])) {
            global $INPUT;
            //try cookie
            list($cookieuser, $cookiesticky, $auth, $servicename) = explode('|', $_COOKIE[DOKU_COOKIE]);
            $cookieuser = base64_decode($cookieuser, true);
            $auth = base64_decode($auth, true);
            $servicename = base64_decode($servicename, true);
            if ($auth === 'oauth') {
                $this->relogin($servicename);
            }
        }

        // do the "normal" plain auth login via form
        return auth_login($user, $pass, $sticky);
    }

    /**
     * @param array $session cookie auth session
     *
     * @return bool
     */
    protected function isSessionValid ($session) {
        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauth');
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

    protected function relogin($servicename) {
        global $INPUT;

        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauth');
        $service     = $hlp->loadService($servicename);
        if(is_null($service)) return false;

        // remember service in session
        session_start();
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'] = $servicename;
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id']      = $INPUT->str('id');
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['params']  = $_GET;

        $_SESSION[DOKU_COOKIE]['oauth-done']['$_REQUEST'] = $_REQUEST;

        if (is_array($INPUT->post->param('do'))) {
            $doPost = key($INPUT->post->arr('do'));
        } else {
            $doPost = $INPUT->post->str('do');
        }
        $doGet = $INPUT->get->str('do');
        if (!empty($doPost)) {
            $_SESSION[DOKU_COOKIE]['oauth-done']['do'] = $doPost;
        } elseif (!empty($doGet)) {
            $_SESSION[DOKU_COOKIE]['oauth-done']['do'] = $doGet;
        }

        session_write_close();

        $service->login();
    }

    /**
     * @param                              $sticky
     * @param OAuth\Plugin\AbstractAdapter $service
     * @param string                       $servicename
     * @param string                       $page
     * @param array                        $params
     *
     * @return bool
     */
    protected function processLogin($sticky, $service, $servicename, $page, $params = array()) {
        $uinfo = $service->getUser();
        $ok = $this->processUser($uinfo, $servicename);
        if(!$ok) {
            return false;
        }
        $this->setUserSession($uinfo, $servicename);
        $this->setUserCookie($uinfo['user'], $sticky, $servicename);
        if(isset($page)) {
            if(!empty($params['id'])) unset($params['id']);
            send_redirect(wl($page, $params, false, '&'));
        }
        return true;
    }

    /**
     * process the user and update the $uinfo array
     *
     * @param $uinfo
     * @param $servicename
     *
     * @return bool
     */
    protected function processUser(&$uinfo, $servicename) {
        $uinfo['user'] = $this->cleanUser((string) $uinfo['user']);
        if(!$uinfo['name']) $uinfo['name'] = $uinfo['user'];

        if(!$uinfo['user'] || !$uinfo['mail']) {
            msg("$servicename did not provide the needed user info. Can't log you in", -1);
            return false;
        }

        // see if the user is known already
        $user = $this->getUserByEmail($uinfo['mail']);
        if($user) {
            $sinfo = $this->getUserData($user);
            // check if the user allowed access via this service
            if(!in_array($this->cleanGroup($servicename), $sinfo['grps'])) {
                msg(sprintf($this->getLang('authnotenabled'), $servicename), -1);
                return false;
            }
            $uinfo['user'] = $user;
            $uinfo['name'] = $sinfo['name'];
            $uinfo['grps'] = array_merge((array) $uinfo['grps'], $sinfo['grps']);
        } elseif(actionOK('register')) {
            $ok = $this->addUser($uinfo, $servicename);
            if(!$ok) {
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
     * @param array $uinfo user info received from the oAuth service
     * @param string $servicename
     *
     * @return bool
     */
    protected function addUser(&$uinfo, $servicename) {
        global $conf;
        $user = $uinfo['user'];
        $count = '';
        while($this->getUserData($user . $count)) {
            if($count) {
                $count++;
            } else {
                $count = 1;
            }
        }
        $user = $user . $count;
        $uinfo['user'] = $user;
        $groups_on_creation = array();
        $groups_on_creation[] = $conf['defaultgroup'];
        $groups_on_creation[] = $this->cleanGroup($servicename); // add service as group
        $uinfo['grps'] = array_merge((array) $uinfo['grps'], $groups_on_creation);

        $ok = $this->triggerUserMod(
            'create',
            array($user, auth_pwgen($user), $uinfo['name'], $uinfo['mail'], $groups_on_creation,)
        );
        if(!$ok) {
            return false;
        }

        // send notification about the new user
        $subscription = new Subscription();
        $subscription->send_register($user, $uinfo['name'], $uinfo['mail']);
        return true;
    }

    /**
     * Find a user by his email address
     *
     * @param $mail
     * @return bool|string
     */
    protected function getUserByEmail($mail) {
        if($this->users === null) $this->_loadUserData();
        $mail = strtolower($mail);

        foreach($this->users as $user => $uinfo) {
            if(strtolower($uinfo['mail']) == $mail) return $user;
        }

        return false;
    }

    /**
     * @param array  $data
     * @param string $service
     */
    protected function setUserSession($data, $service) {
        global $USERINFO;
        global $conf;

        // set up groups
        if(!is_array($data['grps'])) {
            $data['grps'] = array();
        }
        $data['grps'][] = $this->cleanGroup($service);
        $data['grps']   = array_unique($data['grps']);

        $USERINFO                               = $data;
        $_SERVER['REMOTE_USER']                 = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['user']  = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass']  = $data['pass'];
        $_SESSION[DOKU_COOKIE]['auth']['info']  = $USERINFO;
        $_SESSION[DOKU_COOKIE]['auth']['buid']  = auth_browseruid();
        $_SESSION[DOKU_COOKIE]['auth']['time']  = time();
        $_SESSION[DOKU_COOKIE]['auth']['oauth'] = $service;
    }

    /**
     * @param string $user
     * @param bool   $sticky
     * @param string $servicename
     * @param int    $validityPeriodInSeconds optional, per default 1 Year
     */
    private function setUserCookie($user, $sticky, $servicename, $validityPeriodInSeconds = 31536000) {
        $cookie = base64_encode($user).'|'.((int) $sticky).'|'.base64_encode('oauth').'|'.base64_encode($servicename);
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        $time      = $sticky ? (time() + $validityPeriodInSeconds) : 0;
        setcookie(DOKU_COOKIE,$cookie, $time, $cookieDir, '',($conf['securecookie'] && is_ssl()), true);
    }

    /**
     * Unset additional stuff in session on logout
     */
    public function logOff() {
        parent::logOff();

        $this->cleanLogout();
    }

    /**
     * unset auth cookies and session information
     */
    private function cleanLogout() {
        if(isset($_SESSION[DOKU_COOKIE]['oauth-done'])) {
            unset($_SESSION[DOKU_COOKIE]['oauth-done']);
        }
        if(isset($_SESSION[DOKU_COOKIE]['auth'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']);
        }
        $this->setUserCookie('',true,'',-60);
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param null   $grps
     * @return bool|null|string
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
        if($this->getUserByEmail($mail)) {
            msg($this->getLang('emailduplicate'), -1);
            return false;
        }

        return parent::createUser($user, $pwd, $name, $mail, $grps);
    }

    /**
     * Enhance function to check aainst duplicate emails
     *
     * @param string $user
     * @param array  $changes
     * @return bool
     */
    public function modifyUser($user, $changes) {
        global $conf;

        if(isset($changes['mail'])) {
            $found = $this->getUserByEmail($changes['mail']);
            if($found != $user) {
                msg($this->getLang('emailduplicate'), -1);
                return false;
            }
        }

        $ok = parent::modifyUser($user, $changes);

        // refresh session cache
        touch($conf['cachedir'] . '/sessionpurge');

        return $ok;
    }

}

// vim:ts=4:sw=4:et:
