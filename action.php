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
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_loginform');
    }

    /**
     * Start an oAuth login
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_start(Doku_Event &$event, $param) {
        global $INPUT;

        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        $servicename = $INPUT->str('oauthlogin');
        $service = $hlp->loadService($servicename);
        if(is_null($service)) return;

        $service->login();
    }

    /**
     * Add the oAuth login links
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_loginform(Doku_Event &$event, $param) {
        global $ID;

        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        $html = '';
        foreach($hlp->listServices() as $service) {
            if($hlp->getKey($service)) {
                $html .= '<a href="'.wl($ID,array('oauthlogin'=>$service)).'" class="plugin_oauth_'.$service.'"> ';
                $html .= $service;
                $html .= '</a>';
            }
        }
        if(!$html) return;

        /** @var Doku_Form $form */
        $form =& $event->data;
        $pos = $form->findElementByType('closefieldset');

        $form->insertElement(++$pos, form_openfieldset(array('_legend' => $this->getLang('loginwith'), 'class' => 'plugin_oauth')));
        $form->insertElement(++$pos, $html);
        $form->insertElement(++$pos, form_closefieldset());
    }

}
// vim:ts=4:sw=4:et:
