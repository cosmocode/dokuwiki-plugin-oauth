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
	    global $USERINFO, $ID, $INPUT;

        // get form login info
        if(!empty($user)){
            return auth_login($user, $pass, $sticky);
        }

        if($INPUT->has('oa')) {
            /** @var helper_plugin_oauth $hlp */
            $hlp = plugin_load('helper', 'oauth');
            $service = $hlp->loadService($INPUT->str('oa'));
            if(is_null($service)) return false;



            if($service->checkToken()) {
                $uinfo = $service->getUser();
                $this->setUserSession($uinfo);
                return true;
            }
        }

        return false;
    }


    protected function setUserSession($data) {
        global $USERINFO;

        // reopen session
        session_start();

        $USERINFO = $data;
        $_SERVER['REMOTE_USER'] = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $data['pass'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;

        // close session again
        session_write_close();
    }

}

// vim:ts=4:sw=4:et: