<?php
/**
 * DokuWiki Plugin oauth (Helper Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class helper_plugin_oauth extends DokuWiki_Plugin {

    /**
     * Load the needed libraries and initialize the named oAuth service
     *
     * @param string $servicename
     * @return null|\OAuth\Plugin\AbstractAdapter
     */
    public function loadService(&$servicename) {
        $id = getID(); // $ID isn't set in trustExternal, yet

        $servicename = preg_replace('/[^a-zA-Z0-9_]+/', '', $servicename);
        if(!$servicename) return null;

        require_once(__DIR__.'/phpoauthlib/src/OAuth/bootstrap.php');
        require_once(__DIR__.'/classes/AbstractAdapter.php');
        require_once(__DIR__.'/classes/oAuthHTTPClient.php');
        require_once(__DIR__.'/classes/oAuthStorage.php');

        $file = __DIR__.'/classes/'.$servicename.'Adapter.php';
        if(!file_exists($file)) return null;
        require_once($file);
        $class = '\\OAuth\\Plugin\\'.$servicename.'Adapter';

        /** @var \OAuth\Plugin\AbstractAdapter $service */
        $service = new $class($this->redirectURI());
        if(!$service->isInitialized()) {
            msg("Failed to initialize $service authentication service. Check credentials", -1);
            return null;
        }

        // The generic service can be externally configured
        if(is_a($service->oAuth, 'OAuth\\OAuth2\\Service\\Generic')) {
            $service->oAuth->setAuthorizationEndpoint($this->getAuthEndpoint($servicename));
            $service->oAuth->setAccessTokenEndpoint($this->getTokenEndpoint($servicename));
        }

        return $service;
    }

    /**
     * The redirect URI used in all oAuth requests
     *
     * @return string
     */
    public function redirectURI() {
        if ($this->getConf('custom-redirectURI') !== '') {
            return $this->getConf('custom-redirectURI');
        } else {
            return DOKU_URL . DOKU_SCRIPT;
        }
    }

    /**
     * List available Services
     *
     * @param bool $enabledonly list only enabled services
     * @return array
     */
    public function listServices($enabledonly = true) {
        $services = array();
        $files    = glob(__DIR__.'/classes/*Adapter.php');

        foreach($files as $file) {
            $file = basename($file, 'Adapter.php');
            if($file == 'Abstract') continue;
            if($enabledonly && !$this->getKey($file)) continue;
            $services[] = $file;
        }

        return $services;
    }

    /**
     * Return the configured key for the given service
     *
     * @param $service
     * @return string
     */
    public function getKey($service) {
        $service = strtolower($service);
        return $this->getConf($service.'-key');
    }

    /**
     * Return the configured secret for the given service
     *
     * @param $service
     * @return string
     */
    public function getSecret($service) {
        $service = strtolower($service);
        return $this->getConf($service.'-secret');
    }

    /**
     * Return the configured Authentication Endpoint URL for the given service
     *
     * @param $service
     * @return string
     */
    public function getAuthEndpoint($service) {
        $service = strtolower($service);
        return $this->getConf($service.'-authurl');
    }

    /**
     * Return the configured Access Token Endpoint URL for the given service
     *
     * @param $service
     * @return string
     */
    public function getTokenEndpoint($service) {
        $service = strtolower($service);
        return $this->getConf($service.'-tokenurl');
    }

    /**
     * Return the configured User Info Endpoint URL for the given service
     *
     * @param $service
     * @return string
     */
    public function getUserInfoEndpoint($service) {
        $service = strtolower($service);
        return $this->getConf($service.'-userinfourl');
    }

    /**
     * @return array
     */
    public function getValidDomains() {
        if ($this->getConf('mailRestriction') === '') {
            return array();
        }
        $validDomains = explode(',', trim($this->getConf('mailRestriction'), ','));
        $validDomains = array_map('trim', $validDomains);
        return $validDomains;
    }

    /**
     * @param string $mail
     *
     * @return bool
     */
    public function checkMail($mail) {
        $hostedDomains = $this->getValidDomains();

        foreach ($hostedDomains as $validDomain) {
            if(substr($mail, -strlen($validDomain)) === $validDomain) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $session cookie auth session
     *
     * @return bool
     */
    public function validBrowserID ($session) {
        return $session['buid'] == auth_browseruid();
    }

    /**
     * @param array $session cookie auth session
     *
     * @return bool
     */
    public function isSessionTimedOut ($session) {
        global $conf;
        return $session['time'] < time() - $conf['auth_security_timeout'];
    }

    /**
     * @return bool
     */
    public function isGETRequest () {
        global $INPUT;
        $result = $INPUT->server->str('REQUEST_METHOD') === 'GET';
        return $result;
    }

    /**
     * check if we are handling a request to doku.php. Only doku.php defines $updateVersion
     *
     * @return bool
     */
    public function isDokuPHP() {
        global $updateVersion;
        return isset($updateVersion);
    }
}

// vim:ts=4:sw=4:et:
