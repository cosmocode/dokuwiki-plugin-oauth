<?php

namespace OAuth\Plugin;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Service\AbstractService;
use OAuth\Common\Storage\Session;
use OAuth\ServiceFactory;

/**
 * Class AbstractAdapter
 *
 * For each service that shall be used for logging into DokuWiki a subclass of this abstract
 * class has to be created. It defines how to talk to the Service's API to retrieve user
 * information
 *
 * @package OAuth\Plugin
 */
abstract class AbstractAdapter {

    /** @var \OAuth\Common\Service\AbstractService|\OAuth\OAuth2\Service\AbstractService|\OAuth\OAuth2\Service\AbstractService */
    public $oAuth = null;
    /** @var \helper_plugin_oauth */
    protected $hlp = null;
    /** @var \OAuth\Plugin\oAuthStorage */
    protected $storage = null;

    /**
     * Constructor
     *
     * @param $url
     */
    public function __construct($url) {
        $this->hlp = plugin_load('helper', 'oauth');

        $credentials = new Credentials(
            $this->hlp->getKey($this->getAdapterName()),
            $this->hlp->getSecret($this->getAdapterName()),
            $url
        );

        $this->storage = new oAuthStorage();

        $serviceFactory = new ServiceFactory();
        $serviceFactory->setHttpClient(new oAuthHTTPClient());
        $this->oAuth = $serviceFactory->createService(
            $this->getServiceName(),
            $credentials,
            $this->storage,
            $this->getScope()
        );
    }

    /**
     * Check if the initialization worked
     *
     * @return bool
     */
    public function isInitialized() {
        if(is_null($this->oAuth)) return false;
        return true;
    }

    /**
     * Redirects to the service for requesting access
     *
     * This is the first step of oAuth authentication
     *
     * This implementation tries to abstract away differences between oAuth1 and oAuth2,
     * but might need to be overwritten for specific services
     */
    public function login() {
        if(is_a($this->oAuth, 'OAuth\OAuth2\Service\AbstractService')) { /* oAuth2 handling */

            $url = $this->oAuth->getAuthorizationUri();
        } else { /* oAuth1 handling */

            // extra request needed for oauth1 to request a request token :-)
            $token = $this->oAuth->requestRequestToken();

            $url = $this->oAuth->getAuthorizationUri(array('oauth_token' => $token->getRequestToken()));
        }

        send_redirect($url);
    }

    /**
     * Request access token
     *
     * This is the second step of oAuth authentication
     *
     * This implementation tries to abstract away differences between oAuth1 and oAuth2,
     * but might need to be overwritten for specific services
     *
     * @return bool
     */
    public function checkToken() {
        global $INPUT, $conf;

        if(is_a($this->oAuth, 'OAuth\OAuth2\Service\AbstractService')) { /* oAuth2 handling */

            if(!$INPUT->get->has('code')) return false;
            $state = $INPUT->get->str('state', null);

            try {
                $this->oAuth->requestAccessToken($INPUT->get->str('code'), $state);
            } catch (TokenResponseException $e) {
                msg($e->getMessage(), -1);
                if($conf['allowdebug']) msg('<pre>'.hsc($e->getTraceAsString()).'</pre>', -1);
                return false;
            }
        } else { /* oAuth1 handling */

            if(!$INPUT->get->has('oauth_token')) return false;

            $token = $this->storage->retrieveAccessToken($this->getServiceName());

            // This was a callback request from BitBucket, get the token
            try {
                $this->oAuth->requestAccessToken(
                    $INPUT->get->str('oauth_token'),
                    $INPUT->get->str('oauth_verifier'),
                    $token->getRequestTokenSecret()
                );
            } catch (TokenResponseException $e) {
                msg($e->getMessage(), -1);
                return false;
            }
        }

        $validDomains = $this->hlp->getValidDomains();
        if (count($validDomains) > 0) {
            $userData = $this->getUser();
            if (!$this->hlp->checkMail($userData['mail'])) {
                msg(sprintf($this->hlp->getLang("rejectedEMail"),join(', ', $validDomains)),-1);
                send_redirect(wl('', array('do' => 'login',),false,'&'));
            }
        }
        return true;
    }



    /**
     * Return the name of the oAuth service class to use
     *
     * This should match with one of the files in
     * phpoauth/src/oAuth/oAuth[12]/Service/*
     *
     * By default extracts the name from the class name
     *
     * @return string
     */
    public function getServiceName() {
        return $this->getAdapterName();
    }

    /**
     * Retrun the name of this Adapter
     *
     * It specifies which configuration setting should be used
     *
     * @return string
     */
    public function getAdapterName() {
        $name = preg_replace('/Adapter$/', '', get_called_class());
        $name = str_replace('OAuth\\Plugin\\', '', $name);
        return $name;
    }

    /**
     * Return the scope to request
     *
     * This should return the minimal scope needed for accessing the user's data
     *
     * @return array
     */
    public function getScope() {
        return array();
    }

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'email', 'name', 'user', 'grps'
     *
     * @return array
     */
    abstract public function getUser();
}
