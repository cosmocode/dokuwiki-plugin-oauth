<?php

namespace dokuwiki\plugin\oauth;

/**
 * Singleton to manage all oAuth related session and cookie data
 */
class Session
{
    /** @var Session */
    protected static $instance;

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
     * Set the environment needed to verify a login in progress
     *
     * @param string $servicename the name of the service used
     * @param string $id pageID to return to after login
     * @return void
     */
    public function setLoginData($servicename, $id)
    {
        $_SESSION[DOKU_COOKIE]['auth']['oauth'] = [
            'servicename' => $servicename,
            'id' => $id,
        ];
    }

    /**
     * Get the current login environment
     *
     * @return false|array Either [servicename=>*, id=>*] or false
     */
    public function getLoginData()
    {
        return $_SESSION[DOKU_COOKIE]['auth']['oauth'] ?? false;
    }

    /**
     * Clear login environment after login
     *
     * @return void
     */
    public function clearLoginData()
    {
        if (isset($_SESSION[DOKU_COOKIE]['auth']['oauth'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']['oauth']);
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
            !isset($userdata['user']) ||
            !isset($userdata['name']) ||
            !isset($userdata['mail']) ||
            !isset($userdata['grps']) ||
            !is_array($userdata['grps'])
        ) {
            throw new Exception('Missing user data, cannot save to session');
        }

        $USERINFO = $userdata;
        $_SERVER['REMOTE_USER'] = $userdata['user'];

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $userdata['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = 'not-set'; // pass is neither needed nor wanted
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
        return $_SESSION[DOKU_COOKIE]['auth']['info'] ?? false;
    }

    /**
     * Set oAuth info to cookie
     *
     * We use the same cookie as standard DokuWiki, but write different info.
     *
     * @param string $servicename
     * @param string $storageId
     * @return void
     */
    public function setCookie($servicename, $storageId)
    {
        global $conf;
        $validityPeriodInSeconds = 60 * 60 * 24 * 365;
        $time = time() + $validityPeriodInSeconds;
        $cookie = $this->buildCookie($servicename, $storageId, $time);
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        setcookie(
            DOKU_COOKIE,
            $cookie,
            [
                'expires' => $time,
                'path' => $cookieDir,
                'domain' => '',
                'secure' => $conf['securecookie'] && is_ssl(),
                'httponly' => true
            ]
        );
    }

    /**
     * Build the cookie value
     *
     * The storageId is derived from the user's mail address, so the data is signed with
     * the cookie salt to make sure the cookie was issued by us.
     *
     * @param string $servicename the name of the service used
     * @param string $storageId the ID the user's tokens are stored as
     * @param int $expires unix timestamp after which the cookie is no longer accepted
     * @return string the signed cookie value
     */
    public function buildCookie($servicename, $storageId, $expires)
    {
        $data = "$servicename|oauth|$storageId|$expires";
        return $data . '|' . $this->signCookie($data);
    }

    /**
     * Get oAuth info from cookie
     *
     * Cookies with a missing or invalid signature (including those set by older versions) and
     * expired cookies are ignored.
     *
     * @return array|false Either [servicename=>?, storageID=>?] or false if no valid oauth data in cookie
     */
    public function getCookie()
    {
        if (!isset($_COOKIE[DOKU_COOKIE])) return false;
        [$servicename, $oauth, $storageId, $expires, $mac] = sexplode('|', $_COOKIE[DOKU_COOKIE], 5, '');
        if ($oauth !== 'oauth') return false;
        if (!ctype_digit($expires) || (int)$expires < time()) return false;
        if (!hash_equals($this->signCookie("$servicename|oauth|$storageId|$expires"), $mac)) return false;
        return ['servicename' => $servicename, 'storageId' => $storageId];
    }

    /**
     * Sign cookie data with the cookie salt
     *
     * The salt is prefixed to get a key that is separate from the one core uses for its own cookie.
     *
     * @param string $data the cookie data to sign
     * @return string the hex encoded HMAC
     */
    protected function signCookie($data)
    {
        return hash_hmac('sha256', $data, 'oauth' . auth_cookiesalt(false, true));
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
