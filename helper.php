<?php
/**
 * DokuWiki Plugin oauth (Helper Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

use dokuwiki\Extension\Event;
use dokuwiki\plugin\oauth\Service;

require_once(__DIR__ . '/vendor/autoload.php');

/**
 * Basic helper methods for the oauth flow
 */
class helper_plugin_oauth extends DokuWiki_Plugin
{

    /**
     * Load the needed libraries and initialize the named oAuth service
     *
     * @param string $servicename
     * @return null|Service
     */
    public function loadService($servicename)
    {
        $services = $this->listServices(true);
        if (!isset($services[$servicename])) return null;
        return $services[$servicename];
    }

    /**
     * The redirect URI used in all oAuth requests
     *
     * @return string
     */
    public function redirectURI()
    {
        if ($this->getConf('custom-redirectURI') !== '') {
            return $this->getConf('custom-redirectURI');
        } else {
            return DOKU_URL . DOKU_SCRIPT;
        }
    }

    /**
     * List available Services
     *
     * Services returned here, do not have initialized oAuth providers yet!
     *
     * @param bool $enabledonly list only services that have been configured
     * @triggers PLUGIN_OAUTH_BACKEND_REGISTER
     * @return Service[] list of service objects
     */
    public function listServices($enabledonly = true)
    {
        $services = [];
        $event = new Event('PLUGIN_OAUTH_BACKEND_REGISTER', $services);
        $event->advise_before(false);
        $event->advise_after();

        // filter out unconfigured services
        if ($enabledonly) {
            $services = array_filter($services, function ($service) {
                /** @var Service $service */
                return (bool)$service->getKey();
            });
        }

        return $services;
    }

    /**
     * @return array
     */
    public function getValidDomains()
    {
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
    public function checkMail($mail)
    {
        $hostedDomains = $this->getValidDomains();

        foreach ($hostedDomains as $validDomain) {
            if (substr($mail, -strlen($validDomain)) === $validDomain) {
                return true;
            }
        }
        return false;
    }

    /**
     * Display an exception to the user
     *
     * @param Exception $e
     * @param string $prefix - user friendly explanation if available
     */
    public function showException(\Exception $e, $prefix = '')
    {
        global $conf;
        msg('OAuth: ' . $prefix . ' ' . hsc($e->getMessage()), -1);
        if ($conf['allowdebug']) {
            msg('<pre>' . hsc($e->getTraceAsString()) . '</pre>', -1);
        }
    }
}
