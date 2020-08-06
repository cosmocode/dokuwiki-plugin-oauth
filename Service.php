<?php

namespace dokuwiki\plugin\oauth;

use dokuwiki\Extension\ActionPlugin;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Exception\Exception;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\OAuth1\Service\AbstractService as Abstract1Service;
use OAuth\OAuth2\Service\AbstractService as Abstract2Service;
use OAuth\ServiceFactory;

/**
 * Base class to implement a Backend Service for the oAuth Plugin
 */
abstract class Service extends ActionPlugin
{
    /**
     * @var Abstract2Service|Abstract1Service
     * @see getOAuthService() use this to ensure it's intialized
     */
    protected $oAuth;

    // region internal methods

    /**
     * Auto register this plugin with the oAuth authentication plugin
     *
     * @inheritDoc
     */
    public function register(\Doku_Event_Handler $controller)
    {
        $controller->register_hook('PLUGIN_OAUTH_BACKEND_REGISTER', 'AFTER', $this, 'handleRegister');
    }

    /**
     * Auto register this plugin with the oAuth authentication plugin
     *
     * @inheritDoc
     */
    public function handleRegister(\Doku_Event $event, $param)
    {
        $event->data[$this->getServiceID()] = $this;
    }

    /**
     * Initialize the oAuth service
     *
     * @return Abstract2Service|Abstract1Service
     */
    public function getOAuthService()
    {
        if ($this->oAuth !== null) return $this->oAuth;

        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        $credentials = new Credentials(
            $this->getKey(),
            $this->getSecret(),
            $hlp->redirectURI()
        );

        $serviceFactory = new ServiceFactory();
        $serviceFactory->setHttpClient(new HTTPClient());

        $this->oAuth = $serviceFactory->createService(
            $this->getServiceID(),
            $credentials,
            new Storage(),
            $this->getScope()
        );

        return $this->oAuth;
    }

    /**
     * Redirects to the service for requesting access
     *
     * This is the first step of oAuth authentication
     *
     * This implementation tries to abstract away differences between oAuth1 and oAuth2,
     * but might need to be overwritten for specific services
     *
     * @throws TokenResponseException
     */
    public function login()
    {
        $oauth = $this->getOAuthService();

        if (is_a($oauth, 'OAuth\OAuth2\Service\AbstractService')) { /* oAuth2 handling */
            $url = $oauth->getAuthorizationUri();
        } else { /* oAuth1 handling */
            // extra request needed for oauth1 to request a request token
            $token = $oauth->requestRequestToken();
            $url = $oauth->getAuthorizationUri(['oauth_token' => $token->getRequestToken()]);
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
     * Thrown exceptions indicate a non-successful login because of some error, appropriate messages
     * should be shown to the user. A return of false with no exceptions indicates that there was no
     * oauth data at all. This can probably be silently ignored.
     *
     * @return bool true if authentication was successful
     * @throws TokenResponseException
     * @throws TokenNotFoundException
     */
    public function checkToken()
    {
        global $INPUT;

        $oauth = $this->getOAuthService();

        if (is_a($oauth, 'OAuth\OAuth2\Service\AbstractService')) { /* oAuth2 handling */
            if (!$INPUT->get->has('code')) return false;
            $state = $INPUT->get->str('state', null);
            $this->oAuth->requestAccessToken($INPUT->get->str('code'), $state);
        } else { /* oAuth1 handling */
            if (!$INPUT->get->has('oauth_token')) return false;
            $token = $oauth->getStorage()->retrieveAccessToken($this->getServiceID());
            $this->oAuth->requestAccessToken(
                $INPUT->get->str('oauth_token'),
                $INPUT->get->str('oauth_verifier'),
                $token->getRequestTokenSecret()
            );
        }

        // FIXME move this completely to main plugin
        /*
        $validDomains = $this->hlp->getValidDomains();
        if (count($validDomains) > 0) {
            $userData = $this->getUser();
            if (!$this->hlp->checkMail($userData['mail'])) {
                msg(sprintf($this->hlp->getLang("rejectedEMail"), join(', ', $validDomains)), -1);
                send_redirect(wl('', array('do' => 'login',), false, '&'));
            }
        }
        */
        return true;
    }

    /**
     * Return the Service Login Button
     *
     * @return string
     */
    public function loginButton()
    {
        global $ID;

        $attr = buildAttributes([
            'href' => wl($ID, array('oauthlogin' => $this->getServiceID())),
            'class' => 'plugin_oauth_' . $this->getServiceID(),
            'style' => 'background-color: ' . $this->getColor(),
        ]);

        return '<a ' . $attr . '>' . $this->getSvgLogo() . '<span>' . $this->getServiceLabel() . '</span></a> ';
    }

    // endregion

    // region overridable methods

    /**
     * Retrieve the user's data via API
     *
     * The returned array needs to contain at least 'email', 'name', 'user', 'grps'
     *
     * Use the request() method of the oauth object to talk to the API
     *
     * @return array
     * @throws Exception
     * @see getOAuthService()
     */
    abstract public function getUser();

    /**
     * Return the scope to request
     *
     * This should return the minimal scope needed for accessing the user's data
     *
     * @return array
     */
    public function getScope()
    {
        return array();
    }

    /**
     * Return the user friendly name of the service
     *
     * Defaults to ServiceID. You may want to override this.
     *
     * @return string
     */
    public function getServiceLabel()
    {
        return ucfirst($this->getServiceID());
    }

    /**
     * Return the internal name of the Service
     *
     * Defaults to the plugin name (without oauth prefix). This has to match the Service class name in
     * the appropriate lusitantian oauth Service namespace
     *
     * @return string
     */
    public function getServiceID()
    {
        $name = strtolower($this->getPluginName());
        if (substr($name, 0, 5) === 'oauth') {
            $name = substr($name, 5);
        }

        return $name;
    }

    /**
     * Return the button color to use
     *
     * @return string
     */
    public function getColor()
    {
        return '#999';
    }

    /**
     * Return the SVG of the logo for this service
     *
     * Defaults to a logo.svg in the plugin directory
     *
     * @return string
     */
    public function getSvgLogo()
    {
        $logo = DOKU_PLUGIN . $this->getPluginName() . '/logo.svg';
        if (file_exists($logo)) return inlineSVG($logo);
        return '';
    }

    /**
     * The oauth key
     *
     * @return string
     */
    public function getKey()
    {
        return $this->getConf('key');
    }

    /**
     * The oauth secret
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->getConf('secret');
    }

    // endregion
}
