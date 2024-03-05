<?php

use dokuwiki\Extension\ActionPlugin;
use dokuwiki\Extension\EventHandler;
use dokuwiki\Extension\Event;
use dokuwiki\Form\Form;

/**
 * DokuWiki Plugin oauth (Action Component)
 *
 * This manages profile changes and allows the user to change their oauth groups.
 * We use group memberships to define if logins are okay with the given services.
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_oauth_user extends ActionPlugin
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
     * @param EventHandler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(EventHandler $controller)
    {
        global $conf;
        if ($conf['authtype'] != 'oauth') return;

        $conf['profileconfirm'] = false; // password confirmation doesn't work with oauth only users

        $controller->register_hook(
            'HTML_UPDATEPROFILEFORM_OUTPUT',
            'BEFORE',
            $this,
            'handleOldProfileform'
        ); // deprecated
        $controller->register_hook('FORM_UPDATEPROFILE_OUTPUT', 'BEFORE', $this, 'handleProfileform');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handleUsermod');
    }

    /**
     * Save groups for all the services a user has enabled
     *
     * @param Event $event event object by reference
     * @return void
     */
    public function handleUsermod(Event $event)
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
     * @param Event $event event object by reference
     * @return void
     * @deprecated
     */
    public function handleOldProfileform(Event $event)
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
                1,
                $service->getLabel(),
                '',
                'simple',
                [
                    'checked' => (in_array($group, $USERINFO['grps'])) ? 'checked' : '',
                ]
            );

            $form->insertElement(++$pos, $elem);
        }
        $form->insertElement(++$pos, form_closefieldset());
        $form->insertElement(++$pos, form_openfieldset([]));
    }

    /**
     * Add service selection to user profile
     *
     * @param Event $event event object by reference
     * @return void
     */
    public function handleProfileform(Event $event)
    {
        global $USERINFO;
        /** @var auth_plugin_authplain $auth */
        global $auth;

        /** @var Form $form */
        $form = $event->data;
        $pos = $form->findPositionByAttribute('type', 'submit');

        $services = $this->hlp->listServices();
        if (!$services) return;

        $form->addFieldsetOpen($this->getLang('loginwith'), $pos)->addClass('plugin_oauth');

        foreach ($services as $service) {
            $group = $auth->cleanGroup($service->getServiceID());
            $cb = $form->addCheckbox(
                'oauth_group[' . $group . ']',
                $service->getLabel(),
                ++$pos
            );
            if (in_array($group, $USERINFO['grps'])) {
                $cb->attr('checked', 'checked');
            }
        }
        $form->addFieldsetClose(++$pos);
    }
}
