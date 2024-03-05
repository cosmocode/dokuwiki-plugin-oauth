<?php

namespace dokuwiki\plugin\oauth;

use dokuwiki\Extension\EventHandler;
use dokuwiki\Extension\Event;
use dokuwiki\Extension\ActionPlugin;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Session as SessionStorage;
use OAuth\OAuth1\Service\AbstractService as Abstract1Service;
use OAuth\OAuth1\Token\TokenInterface;
use OAuth\OAuth2\Service\AbstractService as Abstract2Service;
use OAuth\OAuth2\Service\Exception\InvalidAuthorizationStateException;
use OAuth\OAuth2\Service\Exception\MissingRefreshTokenException;
use OAuth\ServiceFactory;

/**
 * Base class to implement a Backend Service for the oAuth Plugin
 */
abstract class Adapter extends ActionPlugin
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
    public function register(EventHandler $controller)
    {
        $controller->register_hook('PLUGIN_OAUTH_BACKEND_REGISTER', 'AFTER', $this, 'handleRegister');
    }

    /**
     * Auto register this plugin with the oAuth authentication plugin
     */
    public function handleRegister(Event $event, $param)
    {
        $event->data[$this->getServiceID()] = $this;
    }

    /**
     * Initialize the oAuth service
     *
     * @param string $storageId user based storage key (if available, yet)
     * @throws \OAuth\Common\Exception\Exception
     */
    public function initOAuthService($storageId = '')
    {
        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        $credentials = new Credentials(
            $this->getKey(),
            $this->getSecret(),
            $hlp->redirectURI()
        );

        $serviceFactory = new ServiceFactory();
        $serviceFactory->setHttpClient(new HTTPClient());

        $servicename = $this->getServiceID();
        $serviceclass = $this->registerServiceClass();
        if ($serviceclass) {
            $serviceFactory->registerService($servicename, $serviceclass);
        }

        if ($storageId) {
            $storage = new Storage($storageId);
        } else {
            $storage = new SessionStorage();
        }

        $this->oAuth = $serviceFactory->createService(
            $servicename,
            $credentials,
            $storage,
            $this->getScopes()
        );

        if ($this->oAuth === null) {
            throw new Exception('Failed to initialize Service ' . $this->getLabel());
        }
    }

    /**
     * @return Abstract2Service|Abstract1Service
     * @throws Exception
     */
    public function getOAuthService()
    {
        if ($this->oAuth === null) throw new Exception('OAuth Service not properly initialized');
        return $this->oAuth;
    }

    /**
     * Once a user has been authenticated, the current token storage needs to be made permanent
     *
     * @param string $storageId
     * @throws Exception
     * @throws TokenNotFoundException
     */
    public function upgradeStorage($storageId)
    {
        $oauth = $this->getOAuthService();
        $service = $oauth->service();

        $oldStorage = $oauth->getStorage();
        $newStorage = new Storage($storageId);
        if ($oldStorage->hasAccessToken($service)) {
            $newStorage->storeAccessToken($service, $oldStorage->retrieveAccessToken($service));
        }
        if ($oldStorage->hasAuthorizationState($service)) {
            $newStorage->storeAuthorizationState($service, $oldStorage->retrieveAuthorizationState($service));
        }

        // fixme invalidate current oauth object? reinitialize it?
    }

    /**
     * Refresh a possibly outdated access token
     *
     * Does nothing when the current token is still good to use
     *
     * @return void
     * @throws MissingRefreshTokenException
     * @throws TokenNotFoundException
     * @throws TokenResponseException
     * @throws Exception
     */
    public function refreshOutdatedToken()
    {
        $oauth = $this->getOAuthService();

        if (!$oauth->getStorage()->hasAccessToken($oauth->service())) {
            // no token to refresh
            return;
        }

        $token = $oauth->getStorage()->retrieveAccessToken($oauth->service());
        if (
            $token->getEndOfLife() < 0 ||
            $token->getEndOfLife() - time() > 3600
        ) {
            // token is still good
            return;
        }

        $refreshToken = $token->getRefreshToken();
        $token = $oauth->refreshAccessToken($token);

        // If the IDP did not provide a new refresh token, store the old one
        if (!$token->getRefreshToken()) {
            $token->setRefreshToken($refreshToken);
            $oauth->getStorage()->storeAccessToken($oauth->service(), $token);
        }
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
     * @throws \Exception
     */
    public function login()
    {
        $oauth = $this->getOAuthService();

        // store Farmer animal in oAuth state parameter
        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer');
        $parameters = [];
        if ($farmer && $animal = $farmer->getAnimal()) {
            $parameters['state'] = urlencode(base64_encode(json_encode(
                [
                    'animal' => $animal,
                    'state' => md5(random_int(0, mt_getrandmax())),
                ]
            )));
            $oauth->getStorage()->storeAuthorizationState($oauth->service(), $parameters['state']);
        }

        if (is_a($oauth, Abstract1Service::class)) { /* oAuth1 handling */
            // extra request needed for oauth1 to request a request token
            $token = $oauth->requestRequestToken();
            $parameters['oauth_token'] = $token->getRequestToken();
        }
        $url = $oauth->getAuthorizationUri($parameters);

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
     * @throws \OAuth\Common\Exception\Exception
     * @throws InvalidAuthorizationStateException
     */
    public function checkToken()
    {
        global $INPUT;

        $oauth = $this->getOAuthService();

        if (is_a($oauth, Abstract2Service::class)) {
            if (!$INPUT->get->has('code')) return false;
            $state = $INPUT->get->str('state', null);
            $accessToken = $oauth->requestAccessToken($INPUT->get->str('code'), $state);
        } else {
            if (!$INPUT->get->has('oauth_token')) return false;
            /** @var TokenInterface $token */
            $token = $oauth->getStorage()->retrieveAccessToken($this->getServiceID());
            $accessToken = $oauth->requestAccessToken(
                $INPUT->get->str('oauth_token'),
                $INPUT->get->str('oauth_verifier'),
                $token->getRequestTokenSecret()
            );
        }

        if (
            $accessToken->getEndOfLife() !== $accessToken::EOL_NEVER_EXPIRES &&
            !$accessToken->getRefreshToken()
        ) {
            msg('Service did not provide a Refresh Token. You will be logged out when the session expires.');
        }

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
            'href' => wl($ID, ['oauthlogin' => $this->getServiceID()], false, '&'),
            'class' => 'plugin_oauth_' . $this->getServiceID(),
            'style' => 'background-color: ' . $this->getColor(),
        ]);

        return '<a ' . $attr . '>' . $this->getSvgLogo() . '<span>' . $this->getLabel() . '</span></a> ';
    }
    // endregion

    // region overridable methods

    /**
     * Called on logout
     *
     * If there are required procedures for the service, you can implement them by overriding this.
     *
     * @return void
     */
    public function logout()
    {
    }

    /**
     * Retrieve the user's data via API
     *
     * The returned array needs to contain at least 'email', 'name', 'user' and optionally 'grps'
     *
     * Use the request() method of the oauth object to talk to the API
     *
     * @return array
     * @throws Exception
     * @see getOAuthService()
     */
    abstract public function getUser();

    /**
     * Return the scopes to request
     *
     * This should return the minimal scopes needed for accessing the user's data
     *
     * @return string[]
     */
    public function getScopes()
    {
        return [];
    }

    /**
     * Return the user friendly name of the service
     *
     * Defaults to ServiceID. You may want to override this.
     *
     * @return string
     */
    public function getLabel()
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
        $name = $this->getPluginName();
        if (substr($name, 0, 5) === 'oauth') {
            $name = substr($name, 5);
        }

        return $name;
    }

    /**
     * Register a new Service
     *
     * @return string A fully qualified class name to register as new Service for your ServiceID
     */
    public function registerServiceClass()
    {
        return null;
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
