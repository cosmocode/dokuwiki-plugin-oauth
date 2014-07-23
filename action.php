<?php
/**
 * DokuWiki Plugin oauth (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_oauth extends DokuWiki_Action_Plugin {

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller) {
        global $conf;
        if($conf['authtype'] != 'oauth') return;

        $controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'handle_start');
   
    }

    /**
     * [Custom event handler which performs action]
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */

    public function handle_start(Doku_Event &$event, $param) {
        global $INPUT;
        global $ID;

        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        $servicename = $INPUT->str('oauthlogin');
        $service = $hlp->loadService($servicename);
        if(is_null($service)) return;

        $service->login();
    }

}

// vim:ts=4:sw=4:et:
