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
        global $ID;

        $servicename = preg_replace('/[^a-zA-Z_]+/', '', $servicename);
        if(!$servicename) return null;

        require_once(__DIR__.'/phpoauthlib/src/OAuth/bootstrap.php');
        require_once(__DIR__.'/classes/AbstractAdapter.php');
        require_once(__DIR__.'/classes/oAuthHTTPClient.php');

        $file = __DIR__.'/classes/'.$servicename.'Adapter.php';
        if(!file_exists($file)) return null;
        require_once($file);
        $class = '\\OAuth\\Plugin\\'.$servicename.'Adapter';

        /** @var \OAuth\Plugin\AbstractAdapter $service */
        $service = new $class(wl($ID, array('oa' => $servicename), true, '&'));
        if(!$service->isInitialized()) {
            msg("Failed to initialize $service authentication service. Check credentials", -1);
            return null;
        }

        return $service;
    }

    /**
     * List available Services
     *
     * @return array
     */
    public function listServices() {
        $services = array();
        $files    = glob(__DIR__.'/classes/*Adapter.php');

        foreach($files as $file) {
            $file = basename($file, 'Adapter.php');
            if($file == 'Abstract') continue;
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

}

// vim:ts=4:sw=4:et:
