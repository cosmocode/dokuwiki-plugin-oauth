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
     * @return bool
     */
    public static function hasState()
    {
        return isset($_SESSION[DOKU_COOKIE]['oauth-inprogress']);
    }

    public static function getServiceName()
    {
        return $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'];
    }

    public static function getPid()
    {
        return $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id'];
    }

    public static function getParams()
    {
        return $_SESSION[DOKU_COOKIE]['oauth-inprogress']['params'];
    }

    public function setServiceName($serviceName)
    {
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['service'] = $serviceName;
    }

    public function setPid($pid)
    {
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['id'] = $pid;
    }

    public function setParams($params)
    {
        $_SESSION[DOKU_COOKIE]['oauth-inprogress']['params'] = $params;
    }

    public function clearState()
    {
        unset($_SESSION[DOKU_COOKIE]['oauth-inprogress']);
    }

}
