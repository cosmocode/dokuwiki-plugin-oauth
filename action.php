<?php

use OAuth\Common\Http\Exception\TokenResponseException;

/**
 * DokuWiki Plugin oauth (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_oauth extends DokuWiki_Action_Plugin
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
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handleLoginform');
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handle_profileform');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handle_usermod');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleDoLogin');
    }

    /**
     * Start an oAuth login or restore  environment after successful login
     *
     * @param Doku_Event $event
     * @param mixed $param
     * @return void
     */
    public function handleStart(Doku_Event &$event, $param)
    {
        global $INPUT;

        // login has been done, but there's environment to be restored
        if (isset($_SESSION[DOKU_COOKIE]['oauth-done']['do']) || !empty($_SESSION[DOKU_COOKIE]['oauth-done']['rev'])) {
            $this->restoreSessionEnvironment();
            return;
        }

        // see if a login needs to be started
        $servicename = $INPUT->str('oauthlogin');
        if ($servicename) $this->startOAuthLogin($servicename);
    }

    /**
     * start the oauth login
     *
     * This will redirect to the external service and stop processing in this request.
     * The second part of the login will happen in auth
     *
     * @see auth_plugin_oauth
     */
    protected function startOAuthLogin($servicename)
    {
        global $ID;
        $service = $this->hlp->loadService($servicename);
        if (is_null($service)) return;

        // remember service in session
        session_start();
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'] = $servicename;
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id'] = $ID;
        session_write_close();

        try {
            $service->login(); // redirects
        } catch (TokenResponseException $e) {
            $this->hlp->showException($e, 'login failed');
        }
    }

    /**
     * Restore the request environment that had been set before the oauth shuffle
     */
    protected function restoreSessionEnvironment()
    {
        global $INPUT, $ACT, $TEXT, $PRE, $SUF, $SUM, $RANGE, $DATE_AT, $REV;
        $ACT = $_SESSION[DOKU_COOKIE]['oauth-done']['do'];
        $_REQUEST = $_SESSION[DOKU_COOKIE]['oauth-done']['$_REQUEST'];

        $REV = $INPUT->int('rev');
        $DATE_AT = $INPUT->str('at');
        $RANGE = $INPUT->str('range');
        if ($INPUT->post->has('wikitext')) {
            $TEXT = cleanText($INPUT->post->str('wikitext'));
        }
        $PRE = cleanText(substr($INPUT->post->str('prefix'), 0, -1));
        $SUF = cleanText($INPUT->post->str('suffix'));
        $SUM = $INPUT->post->str('summary');

        unset($_SESSION[DOKU_COOKIE]['oauth-done']);
    }

    /**
     * Save groups for all the services a user has enabled
     *
     * @param Doku_Event $event event object by reference
     * @param mixed $param [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_usermod(Doku_Event $event, $param)
    {
        global $ACT;
        global $USERINFO;
        global $auth;
        global $INPUT;

        if ($event->data['type'] != 'modify') return;
        if ($ACT != 'profile') return;

        // we want to modify the user's groups
        $groups = $USERINFO['grps']; //current groups
        if (isset($event->data['params'][1]['grps'])) {
            // something already defined new groups
            $groups = $event->data['params'][1]['grps'];
        }

        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        // get enabled and configured services
        $enabled = $INPUT->arr('oauth_group');
        $services = $hlp->listServices();
        $services = array_map(array($auth, 'cleanGroup'), $services);

        // add all enabled services as group, remove all disabled services
        foreach ($services as $service) {
            if (isset($enabled[$service])) {
                $groups[] = $service;
            } else {
                $idx = array_search($service, $groups);
                if ($idx !== false) unset($groups[$idx]);
            }
        }
        $groups = array_unique($groups);

        // add new group array to event data
        $event->data['params'][1]['grps'] = $groups;

    }

    /**
     * Add service selection to user profile
     *
     * @param Doku_Event $event event object by reference
     * @param mixed $param [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_profileform(Doku_Event $event, $param)
    {
        global $USERINFO;
        /** @var auth_plugin_authplain $auth */
        global $auth;

        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        /** @var Doku_Form $form */
        $form =& $event->data;
        $pos = $form->findElementByAttribute('type', 'submit');

        $services = $hlp->listServices();
        if (!$services) return;

        $form->insertElement($pos, form_closefieldset());
        $form->insertElement(++$pos,
            form_openfieldset(array('_legend' => $this->getLang('loginwith'), 'class' => 'plugin_oauth')));
        foreach ($services as $service) {
            $group = $auth->cleanGroup($service);
            $elem = form_makeCheckboxField(
                'oauth_group[' . $group . ']',
                1, $service, '', 'simple',
                array(
                    'checked' => (in_array($group, $USERINFO['grps'])) ? 'checked' : '',
                )
            );

            $form->insertElement(++$pos, $elem);
        }
        $form->insertElement(++$pos, form_closefieldset());
        $form->insertElement(++$pos, form_openfieldset(array()));
    }

    /**
     * Add the oAuth login links
     *
     * @param Doku_Event $event event object by reference
     * @param mixed $param
     * @return void
     */
    public function handleLoginform(Doku_Event $event, $param)
    {
        /** @var Doku_Form $form */
        $form = $event->data;
        $html = '';

        $validDomains = $this->hlp->getValidDomains();

        if (count($validDomains) > 0) {
            $html .= sprintf($this->getLang('eMailRestricted'), join(', ', $validDomains));
        }

        foreach ($this->hlp->listServices() as $service) {
            $html .= $service->loginButton();
        }
        if (!$html) return;

        $form->_content[] = form_openfieldset(array(
            '_legend' => $this->getLang('loginwith'),
            'class' => 'plugin_oauth',
        ));
        $form->_content[] = $html;
        $form->_content[] = form_closefieldset();
    }

    /**
     * When singleservice is wanted, do not show login, but execute login right away
     *
     * @param Doku_Event $event
     * @param $param
     * @return bool
     */
    public function handleDoLogin(Doku_Event $event, $param)
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

        $url = wl($ID, array('oauthlogin' => $service->getServiceID()), true, '&');
        send_redirect($url);
        return true; // never reached
    }

}
