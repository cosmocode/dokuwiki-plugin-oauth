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
        global $conf;
        global $USERINFO;

        // are we in login progress?
        if(isset($_SESSION[DOKU_COOKIE]['oauth-inprogress'])) {
            $servicename = $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'];
            $page        = $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id'];

            unset($_SESSION[DOKU_COOKIE]['oauth-inprogress']);
        }

        // check session for existing oAuth login data
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        if(!isset($servicename) && isset($session['oauth'])) {
            $servicename = $session['oauth'];
            // check if session data is still considered valid
            if(($session['time'] >= time() - $conf['auth_security_timeout']) &&
                ($session['buid'] == auth_browseruid())
            ) {

                $_SERVER['REMOTE_USER'] = $session['user'];
                $USERINFO               = $session['info'];
                return true;
            }
        }

        // either we're in oauth login or a previous log needs to be rechecked
        if(isset($servicename)) {
            /** @var helper_plugin_oauth $hlp */
            $hlp     = plugin_load('helper', 'oauth');
            $service = $hlp->loadService($servicename);
            if(is_null($service)) return false;

            if($service->checkToken()) {


                $uinfo = $service->getUser();

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
                } elseif (actionOK('register')) {
                    // new user, create him - making sure the login is unique by adding a number if needed
                    $user  = $uinfo['user'];
                    $count = '';
                    while($this->getUserData($user . $count)) {
                        if($count) {
                            $count++;
                        } else {
                            $count = 1;
                        }
                    }
                    $user            = $user . $count;
                    $uinfo['user']   = $user;
                    $groups_on_creation = array();
                    $groups_on_creation[] = $conf['defaultgroup'];
                    $groups_on_creation[] = $this->cleanGroup($servicename); // add service as group
                    $uinfo['grps'] = array_merge((array) $uinfo['grps'], $groups_on_creation);

                    $ok = $this->triggerUserMod('create',array($user, auth_pwgen($user), $uinfo['name'], $uinfo['mail'],
                                                          $groups_on_creation));
                    if(!$ok) {
                        msg('something went wrong creating your user account. please try again later.', -1);
                        return false;
                    }

                    // send notification about the new user
                    $subscription = new Subscription();
                    $subscription->send_register($user, $uinfo['name'], $uinfo['mail']);
                } else {
                    msg('Self-Registration is currently disabled. Please ask your DokuWiki administrator to create your account manually.', -1);
                    return false;
                }

                // set user session
                $this->setUserSession($uinfo, $servicename);

                $cookie = base64_encode($user).'|'.((int) $sticky).'|'.base64_encode('oauth').'|'.base64_encode($servicename);
                $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
                $time      = $sticky ? (time() + 60 * 60 * 24 * 365) : 0;
                setcookie(DOKU_COOKIE,$cookie, $time, $cookieDir, '',($conf['securecookie'] && is_ssl()), true);

                if(isset($page)) {
                    send_redirect(wl($page));
                }
                return true;
            } else {
                $this->relogin($servicename);
            }

            unset($_SESSION[DOKU_COOKIE]['auth']);
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

        $str_vars = array('wikitext', 'prefix', 'suffix', 'summary', 'sectok', 'target', 'range', 'rev', 'at');
        foreach ($str_vars as $input_var) {
            if ($INPUT->str($input_var) !== '') {
                $_SESSION[DOKU_COOKIE]['oauth-done'][$input_var] = $INPUT->str($input_var);
            }

            if ($INPUT->post->str($input_var) !== '') {
                $_SESSION[DOKU_COOKIE]['oauth-done']['post'][$input_var] = $INPUT->post->str($input_var);
            }

            if ($INPUT->get->str($input_var) !== '') {
                $_SESSION[DOKU_COOKIE]['oauth-done']['get'][$input_var] = $INPUT->get->str($input_var);
            }
        }

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
     * Unset additional stuff in session on logout
     */
    public function logOff() {
        parent::logOff();

        if(isset($_SESSION[DOKU_COOKIE]['auth']['buid'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['buid']);
        }
        if(isset($_SESSION[DOKU_COOKIE]['auth']['time'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['time']);
        }
        if(isset($_SESSION[DOKU_COOKIE]['auth']['oauth'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['oauth']);
        }
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
     * Enhance function to check aainst duplicate emails
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
