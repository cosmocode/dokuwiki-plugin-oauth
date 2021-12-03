<?php

namespace dokuwiki\plugin\oauth;

/**
 * Singleton to manage all oAuth related session and cookie data
 */
class Session
{
    /** @var Session */
    protected static $instance = null;

    /**
     * hidden constructor
     */
    protected function __construct()
    {
    }

    /**
     * Get Singleton Instance
     *
     * @return Session
     */
    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new Session();
        }
        return self::$instance;
    }

    /**
     * Set a service and guid for a login in progress
     *
     * @param string $servicename
     * @param string $guid
     * @return void
     */
    public function setLoginData($servicename, $guid)
    {
        $_SESSION[DOKU_COOKIE]['auth']['oauth']['service'] = $servicename;
        $_SESSION[DOKU_COOKIE]['auth']['oauth']['guid'] = $guid;
    }

    /**
     * Get currently used login service
     *
     * @return false|array Either [servicename=>*,guid=>*] or false
     */
    public function getLoginData()
    {
        if (
            isset($_SESSION[DOKU_COOKIE]['auth']['oauth']['service']) and
            isset($_SESSION[DOKU_COOKIE]['auth']['oauth']['guid'])

        ) {
            return [
                'servicename' => $_SESSION[DOKU_COOKIE]['auth']['oauth']['service'],
                'guid' => $_SESSION[DOKU_COOKIE]['auth']['oauth']['guid'],
            ];
        }
        return false;
    }

    /**
     * Remove login service from session
     * @return void
     */
    public function clearLoginData()
    {
        if (isset($_SESSION[DOKU_COOKIE]['auth']['oauth']['service'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['oauth']['service']);
        }
        if (isset($_SESSION[DOKU_COOKIE]['auth']['oauth']['guid'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['oauth']['guid']);
        }
    }

    /**
     * This basically duplicates what DokuWiki does when a user is logged in
     *
     * @param array $userdata
     * @param bool $resettime Set a new session time? False only when restoring from session
     * @return void
     * @throws Exception
     */
    public function setUser($userdata, $resettime = true)
    {
        global $USERINFO;

        if (
            !isset($userdata['user']) or
            !isset($userdata['name']) or
            !isset($userdata['mail']) or
            !isset($userdata['grps']) or
            !is_array($userdata['grps'])
        ) {
            throw new Exception('Missing user data, cannot save to session');
        }

        $USERINFO = $userdata;
        $_SERVER['REMOTE_USER'] = $userdata['user'];

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $userdata['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $userdata['pass'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
        if ($resettime) {
            $_SESSION[DOKU_COOKIE]['auth']['time'] = time();
        }
    }

    /**
     * The user data currently saved in the session if any
     *
     * @return false|array
     */
    public function getUser()
    {
        if (isset($_SESSION[DOKU_COOKIE]['auth']['info'])) {
            return $_SESSION[DOKU_COOKIE]['auth']['info'];
        }
        return false;
    }

    /**
     * Set oAuth info to cookie
     *
     * We use the same cookie as standard DokuWiki, but write different info.
     *
     * @param string $servicename
     * @param string $guid
     * @return void
     */
    public function setCookie($servicename, $guid)
    {
        global $conf;
        $validityPeriodInSeconds = 60 * 60 * 24 * 365;
        $cookie = "$servicename|oauth|$guid";
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        $time = time() + $validityPeriodInSeconds;
        setcookie(DOKU_COOKIE, $cookie, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
    }

    /**
     * Get oAuth info from cookie
     *
     * @return array|false Either [servicename=>?, guid=>?] or false if no oauth data in cookie
     */
    public function getCookie()
    {
        if (!isset($_COOKIE[DOKU_COOKIE])) return false;
        list($servicename, $oauth, $guid) = explode('|', $_COOKIE[DOKU_COOKIE]);
        if ($oauth !== 'oauth') return false;
        return ['servicename' => $servicename, 'guid' => $guid];
    }

    /**
     * Is any auth data in the session currently trustworthy?
     * @return bool
     */
    public function isValid()
    {
        global $conf;

        if (!isset($_SESSION[DOKU_COOKIE]['auth']['buid'])) return false;
        if (!isset($_SESSION[DOKU_COOKIE]['auth']['time'])) return false;
        if ($_SESSION[DOKU_COOKIE]['auth']['buid'] != auth_browseruid()) return false;
        if ($_SESSION[DOKU_COOKIE]['auth']['time'] < time() - $conf['auth_security_timeout']) return false;

        return true;
    }

    /**
     * Clear the session from auth related data
     * @return void
     */
    public function clear()
    {
        //FIXME clear cookie?
        $this->clearLoginData();

    }
}
