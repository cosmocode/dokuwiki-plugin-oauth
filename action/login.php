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
        $controller->register_hook('ACTION_DENIED_TPLCONTENT', 'BEFORE', $this, 'handleDeniedForm');
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

        // remove login form if single service is set
        $singleService = $this->getConf('singleService');
        if ($singleService) {
            $form->_content = [];
        }

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

        // remove login form if local logins are denied
        $denyLocal = $this->getConf('denyLocal');
        $hideLocal = $this->getConf('hideLocal');
        if ($denyLocal or $hideLocal) {
            do {
                $form->removeElement(0);
            } while ($form->elementCount() > 0);
        }

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

        $html .= '<div>';
        foreach ($this->hlp->listServices() as $service) {
            $html .= $service->loginButton();
        }
        $html .= '</div>';

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
        global $INPUT;

        if ($event->data != 'login' && $event->data != 'denied') return true;

        $singleService = $this->getConf('singleService');
        if (!$singleService) return true;

        if ($INPUT->server->str('REMOTE_USER') !== '') {
            // already logged in
            return true;
        }

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

    /**
     * Do not show a login form on restricted pages when SingleService is enabled
     *
     * This can happen when the user is already logged in, but still doesn't have enough permissions
     *
     * @param Doku_Event $event
     * @return void
     */
    public function handleDeniedForm(Doku_Event $event)
    {
        if ($this->getConf('singleService')) {
            $event->preventDefault();
            $event->stopPropagation();
        }
    }
}
