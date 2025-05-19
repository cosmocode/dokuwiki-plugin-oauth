<?php

use dokuwiki\plugin\oauth\OAuthManager;
use dokuwiki\plugin\oauth\Session;
use dokuwiki\Subscriptions\RegistrationSubscriptionSender;
use OAuth\Common\Exception\Exception as OAuthException;

/**
 * DokuWiki Plugin oauth (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class auth_plugin_oauth extends auth_plugin_authplain
{
    /** @var helper_plugin_oauth */
    protected $hlp;

    /** @var OAuthManager */
    protected $om;

    // region standard auth methods

    /** @inheritDoc */
    public function __construct()
    {
        parent::__construct();
        $this->cando['external'] = true;
        $this->hlp = $this->loadHelper('oauth');
    }

    /** @inheritDoc */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $INPUT;

        // handle redirects from farmer to animal wiki instances
        if ($INPUT->has('state') && plugin_load('helper', 'farmer')) {
            $this->handleFarmState($INPUT->str('state'));
        }

        try {
            // either oauth or "normal" plain auth login via form
            $this->om = new OAuthManager();
            if ($this->om->continueFlow()) return true;
            if ($this->getConf('singleService')) {
                return false; // no normal login in singleService mode
            }
            return null; // triggers the normal auth_login()
        } catch (OAuthException $e) {
            $this->hlp->showException($e);
            auth_logoff(); // clears all session and cookie data
            return false;
        }
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @inheritdoc
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null)
    {
        if ($this->getUserByEmail($mail)) {
            msg($this->getLang('emailduplicate'), -1);
            return false;
        }

        return parent::createUser($user, $pwd, $name, $mail, $grps);
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @inheritdoc
     */
    public function modifyUser($user, $changes)
    {
        global $conf;

        if (isset($changes['mail'])) {
            $found = $this->getUserByEmail($changes['mail']);
            if ($found && $found != $user) {
                msg($this->getLang('emailduplicate'), -1);
                return false;
            }
        }

        $ok = parent::modifyUser($user, $changes);

        // refresh session cache
        touch($conf['cachedir'] . '/sessionpurge');
        return $ok;
    }

    /**
     * Unset additional stuff in session on logout
     */
    public function logOff()
    {
        parent::logOff();
        if (isset($this->om)) {
            $this->om->logout();
        }
        (Session::getInstance())->clear();
    }

    // endregion

    /**
     * Register a new user logged in by oauth
     *
     * It ensures the username is unique, by adding a number if needed.
     * Default and service name groups are set here.
     * Registration notifications are triggered.
     *
     * @param array $userinfo This will be updated with the new username
     * @param string $servicename
     *
     * @return bool
     * @todo - should this be part of the OAuthManager class instead?
     */
    public function registerOAuthUser(&$userinfo, $servicename)
    {
        global $conf;
        $user = $userinfo['user'];
        $count = '';
        while ($this->getUserData($user . $count)) {
            if ($count) {
                $count++;
            } else {
                $count = 1;
            }
        }
        $user .= $count;
        $userinfo['user'] = $user;
        $groups_on_creation = [];
        $groups_on_creation[] = $conf['defaultgroup'];
        $groups_on_creation[] = $this->cleanGroup($servicename); // add service as group
        $userinfo['grps'] = array_merge((array)$userinfo['grps'], $groups_on_creation);

        // the password set here will remain unknown to the user
        $ok = $this->triggerUserMod(
            'create',
            [
                $user,
                auth_pwgen($user),
                $userinfo['name'],
                $userinfo['mail'],
                $userinfo['grps'],
            ]
        );
        if (!$ok) {
            return false;
        }

        // send notification about the new user
        $subscriptionSender = new RegistrationSubscriptionSender();
        $subscriptionSender->sendRegister($user, $userinfo['name'], $userinfo['mail']);

        return true;
    }

    /**
     * Find a user by email address
     *
     * @param $mail
     * @return bool|string
     */
    public function getUserByEmail($mail)
    {
        if ($this->users === null) {
            $this->loadUserData();
        }
        $mail = strtolower($mail);

        foreach ($this->users as $user => $userinfo) {
            if (strtolower($userinfo['mail']) === $mail) return $user;
        }

        return false;
    }

    /**
     * Fall back to plain auth strings
     *
     * @inheritdoc
     */
    public function getLang($id)
    {
        $result = parent::getLang($id);
        if ($result) return $result;

        $parent = new auth_plugin_authplain();
        return $parent->getLang($id);
    }

    /**
     * Get an option
     *
     * @param string $option The name of the wanted option
     *
     * @return string  The option value
     */
    public function getOption($option)
    {
        return $this->getConf($option);
    }

    /**
     * Farmer plugin support
     *
     * When coming back to farmer instance via OAUTH redirectURI, we need to redirect again
     * to a proper animal instance detected from $state
     *
     * @param $state
     */
    protected function handleFarmState($state)
    {
        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer', false, true);
        $data = json_decode(base64_decode(urldecode($state)));
        if (empty($data->animal) || $farmer->getAnimal() == $data->animal) {
            return;
        }
        $animal = $data->animal;
        $allAnimals = $farmer->getAllAnimals();
        if (!in_array($animal, $allAnimals)) {
            msg('Animal ' . $animal . ' does not exist!');
            return;
        }
        global $INPUT;
        $url = $farmer->getAnimalURL($animal) . '/doku.php?' . $INPUT->server->str('QUERY_STRING');
        send_redirect($url);
    }
}
