<?php

namespace dokuwiki\plugin\oauth;

/**
 * Class SessionManager
 * @package dokuwiki\plugin\oauth
 *
 * Manages auth session data
 */
class SessionManager
{
    /**
     * Authentication state to be preserved in session
     *
     * @var AuthState
     */
    protected static $state = null;

    /**
     * @var SessionManager
     */
    protected static $instance = null;

    protected function __construct()
    {
        self::restoreState();
        if (self::$state === null) {
            self::$state = new AuthState();
        }
    }

    /**
     * @return SessionManager
     */
    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new SessionManager();
        }
        return self::$instance;
    }

    public function saveState()
    {
        session_start();
        $_SESSION[DOKU_COOKIE]['oauth-state'] = serialize(self::$state);
        session_write_close();
    }

    /**
     * @return AuthState
     */
    public static function restoreState()
    {
        if (isset($_SESSION[DOKU_COOKIE]['oauth-state'])) {
            self::$state = unserialize($_SESSION[DOKU_COOKIE]['oauth-state']);
        }
        return self::$state;
    }

    /**
     * @return bool
     */
    public function isInProgress()
    {
        return self::$state->isInProgress();
    }

    public function getServiceName()
    {
        return self::$state->getService();
    }

    public function getPid()
    {
        return self::$state->getId();
    }

    public function getParams()
    {
        return self::$state->getLoginParams();
    }

    public function getDo()
    {
        return self::$state->getDo();
    }

    public function getRequest()
    {
        return self::$state->getRequest();
    }

    public function getRev()
    {
        return self::$state->getRev();
    }

    public function setServiceName($serviceName)
    {
        self::$state->setService($serviceName);
    }

    public function setPid($pid)
    {
        self::$state->setId($pid);
    }

    public function setParams($params)
    {
        self::$state->setLoginParams($params);
    }

    public function setDo($do)
    {
        self::$state->setDo($do);
    }

    public function setRequest($request)
    {
        self::$state->setRequest($request);
    }

    public function setInProgress($progress)
    {
        self::$state->setInProgress($progress);
    }

}
