<?php

/**
 * DokuWiki Plugin oauth (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_oauth_user extends DokuWiki_Action_Plugin
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

        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handleProfileform');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handleUsermod');
    }
    /**
     * Save groups for all the services a user has enabled
     *
     * @param Doku_Event $event event object by reference
     * @return void
     */
    public function handleUsermod(Doku_Event $event)
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

        // get enabled and configured services
        $enabled = $INPUT->arr('oauth_group');
        $services = array_keys($this->hlp->listServices());
        $services = array_map([$auth, 'cleanGroup'], $services);

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
     * @return void
     */
    public function handleProfileform(Doku_Event $event)
    {
        global $USERINFO;
        /** @var auth_plugin_authplain $auth */
        global $auth;

        /** @var Doku_Form $form */
        $form = $event->data;
        $pos = $form->findElementByAttribute('type', 'submit');

        $services = $this->hlp->listServices();
        if (!$services) return;

        $form->insertElement($pos, form_closefieldset());
        $form->insertElement(
            ++$pos,
            form_openfieldset(['_legend' => $this->getLang('loginwith'), 'class' => 'plugin_oauth'])
        );
        foreach ($services as $service) {
            $group = $auth->cleanGroup($service->getServiceID());
            $elem = form_makeCheckboxField(
                'oauth_group[' . $group . ']',
                1, $service->getServiceLabel(), '', 'simple',
                [
                    'checked' => (in_array($group, $USERINFO['grps'])) ? 'checked' : '',
                ]
            );

            $form->insertElement(++$pos, $elem);
        }
        $form->insertElement(++$pos, form_closefieldset());
        $form->insertElement(++$pos, form_openfieldset([]));
    }
}
