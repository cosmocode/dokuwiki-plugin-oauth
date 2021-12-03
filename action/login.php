<?php

use dokuwiki\Form\Form;
use dokuwiki\plugin\oauth\OAuthManager;
use OAuth\Common\Http\Exception\TokenResponseException;

/**
 * DokuWiki Plugin oauth (Action Component)
 *
 * This adds buttons to the login page and initializes the oAuth flow by redirecting the user
 * to the third party service
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_oauth_login extends DokuWiki_Action_Plugin
{
    /** @var helper_plugin_oauth */
    protected $hlp;

    /**
     * Constructor
     *
     * Initializes the helper
     */
    public function __construct()
    {
        $this->hlp = plugin_load('helper', 'oauth');
    }

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        global $conf;
        if ($conf['authtype'] != 'oauth') return;

        $conf['profileconfirm'] = false; // password confirmation doesn't work with oauth only users

        $controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'handleStart');
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handleOldLoginForm'); // @deprecated
        $controller->register_hook('FORM_LOGIN_OUTPUT', 'BEFORE', $this, 'handleLoginForm');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleDoLogin');
    }

    /**
     * Start an oAuth login or restore  environment after successful login
     *
     * @param Doku_Event $event
     * @return void
     */
    public function handleStart(Doku_Event $event)
    {
        global $INPUT;

        // see if a login needs to be started
        $servicename = $INPUT->str('oauthlogin');
        if (!$servicename) return;

        try {
            $om = new OAuthManager();
            $om->startFlow($servicename);
        } catch (TokenResponseException|Exception $e) {
            $this->hlp->showException($e, 'login failed');
        }
    }

    /**
     * Add the oAuth login links to login form
     *
     * @param Doku_Event $event event object by reference
     * @return void
     * @deprecated can be removed in the future
     */
    public function handleOldLoginForm(Doku_Event $event)
    {
        /** @var Doku_Form $form */
        $form = $event->data;
        $html = $this->prepareLoginButtons();
        if (!$html) return;

        $form->_content[] = form_openfieldset(
            [
                '_legend' => $this->getLang('loginwith'),
                'class' => 'plugin_oauth',
            ]
        );
        $form->_content[] = $html;
        $form->_content[] = form_closefieldset();
    }

    /**
     * Add the oAuth login links to login form
     *
     * @param Doku_Event $event event object by reference
     * @return void
     * @deprecated can be removed in the future
     */
    public function handleLoginForm(Doku_Event $event)
    {
        /** @var Form $form */
        $form = $event->data;
        $html = $this->prepareLoginButtons();
        if (!$html) return;

        $form->addFieldsetOpen($this->getLang('loginwith'))->addClass('plugin_oauth');
        $form->addHTML($html);
        $form->addFieldsetClose();
    }

    /**
     * Create HTML for the various login buttons
     *
     * @return string the HTML
     */
    protected function prepareLoginButtons()
    {
        $html = '';

        $validDomains = $this->hlp->getValidDomains();

        if (count($validDomains) > 0) {
            $html .= '<p class="plugin-oauth-emailrestriction">' . sprintf(
                    $this->getLang('eMailRestricted'),
                    '<b>' . join(', ', $validDomains) . '</b>'
                ) . '</p>';
        }

        foreach ($this->hlp->listServices() as $service) {
            $html .= $service->loginButton();
        }

        return $html;
    }

    /**
     * When singleservice is wanted, do not show login, but execute login right away
     *
     * @param Doku_Event $event
     * @return bool
     */
    public function handleDoLogin(Doku_Event $event)
    {
        global $ID;

        if ($event->data != 'login') return true;

        $singleService = $this->getConf('singleService');
        if (!$singleService) return true;

        $enabledServices = $this->hlp->listServices();
        if (count($enabledServices) !== 1) {
            msg($this->getLang('wrongConfig'), -1);
            return false;
        }

        $service = array_shift($enabledServices);

        $url = wl($ID, ['oauthlogin' => $service->getServiceID()], true, '&');
        send_redirect($url);
        return true; // never reached
    }

}
