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

    public function __construct() {
        parent::__construct();


        $this->cando['external'] = true;
    }


    function trustExternal($user, $pass, $sticky = false) {
	    global $INPUT;
        global $conf;
        global $USERINFO;

        $servicename = $INPUT->str('oa');

        // check session for existing oAuth login data
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        if(!$servicename && isset($session['oauth'])) {
            $servicename = $session['oauth'];
            // check if session data is still considered valid
            if( ($session['time'] >= time() - $conf['auth_security_timeout']) &&
                ($session['buid'] == auth_browseruid())) {

                $_SERVER['REMOTE_USER'] = $session['user'];
                $USERINFO               = $session['info'];
                return true;
            }
        }

        // either we're in oauth login or a previous log needs to be rechecked
        if($servicename) {
            /** @var helper_plugin_oauth $hlp */
            $hlp = plugin_load('helper', 'oauth');
            $service = $hlp->loadService($servicename);
            if(is_null($service)) return false;

            // get the token
            if($service->checkToken()) {
                $uinfo = $service->getUser();
                $this->setUserSession($uinfo, $servicename);
                return true;
            }

            return false; // something went wrong during oAuth login
        }


        // do the "normal" plain auth login via form
        return auth_login($user, $pass, $sticky);
    }

    /**
     * @param array $data
     * @param string $service
     */
    protected function setUserSession($data, $service) {
        global $USERINFO;
        global $conf;

        // set up groups
        if(!is_array($data['grps'])) {
            $data['grps'] = array();
        }
        $data['grps'][] = $conf['defaultgroup'];
        $data['grps'][] = $this->cleanGroup($service);

        $USERINFO = $data;
        $_SERVER['REMOTE_USER'] = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $data['pass'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
        $_SESSION[DOKU_COOKIE]['auth']['time'] = time();
        $_SESSION[DOKU_COOKIE]['auth']['oauth'] = $service;
    }

}

// vim:ts=4:sw=4:et: