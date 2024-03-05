<?php

// phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols

/**
 * DokuWiki Plugin oauth (Helper Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

use dokuwiki\Extension\Plugin;
use dokuwiki\Extension\Event;
use dokuwiki\plugin\oauth\Adapter;

require_once(__DIR__ . '/vendor/autoload.php'); // @todo can be removed with next dw release

/**
 * Basic helper methods for the oauth flow
 */
class helper_plugin_oauth extends Plugin
{
    /**
     * Load the needed libraries and initialize the named oAuth service
     *
     * @param string $servicename
     * @return null|Adapter
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
     * @return Adapter[] list of service objects
     */
    public function listServices($enabledonly = true)
    {
        $services = [];
        $event = new Event('PLUGIN_OAUTH_BACKEND_REGISTER', $services);
        $event->advise_before(false);
        $event->advise_after();

        // filter out unconfigured services
        if ($enabledonly) {
            $services = array_filter($services, static fn($service) =>
                /** @var Adapter $service */
                (bool)$service->getKey());
        }

        return $services;
    }

    /**
     * @return array
     */
    public function getValidDomains()
    {
        if ($this->getConf('mailRestriction') === '') {
            return [];
        }
        $validDomains = explode(',', trim($this->getConf('mailRestriction'), ','));
        return array_map('trim', $validDomains);
    }

    /**
     * @param string $mail
     *
     * @return bool
     */
    public function checkMail($mail)
    {
        $validDomains = $this->getValidDomains();
        if (empty($validDomains)) return true;

        foreach ($validDomains as $validDomain) {
            if (str_ends_with($mail, $validDomain)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Display an exception to the user
     *
     * @param Exception $e
     * @param string $friendly - user friendly explanation if available
     */
    public function showException(Exception $e, $friendly = '')
    {
        global $conf;

        $msg = $e->getMessage();

        // translate the message if possible, using context if available
        $trans = $this->getLang($msg);
        if ($trans) {
            if ($e instanceof \dokuwiki\plugin\oauth\Exception) {
                $context = $e->getContext();
                $trans = sprintf($trans, ...$context);
            }
            $msg = $trans;
        }

        msg('OAuth: ' . $friendly . ' ' . hsc($msg), -1);
        if ($conf['allowdebug']) {
            $msg = get_class($e) . ' at ' . $e->getFile() . ':' . $e->getLine() . '<br>';
            $msg .= hsc($e->getTraceAsString());
            msg("<pre>$msg</pre>", -1);
        }
    }
}
