<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;
use OAuth\Common\Storage\Exception\CodeVerifierNotFoundException;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SymfonySession implements TokenStorageInterface
{
    private $session;
    private $sessionVariableName;
    private $stateVariableName;
    private $verifierVariableName;

    /**
     * @param SessionInterface $session
     * @param bool $startSession
     * @param string $sessionVariableName
     * @param string $stateVariableName
     * @param string $verifierVariableName
     */
    public function __construct(
        SessionInterface $session,
        $startSession = true,
        $sessionVariableName = 'lusitanian_oauth_token',
        $stateVariableName = 'lusitanian_oauth_state',
        $verifierVariableName = 'lusitanian_oauth_verifier'
    ) {
        $this->session = $session;
        $this->sessionVariableName = $sessionVariableName;
        $this->stateVariableName = $stateVariableName;
        $this->verifierVariableName = $verifierVariableName;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if ($this->hasAccessToken($service)) {
            // get from session
            $tokens = $this->session->get($this->sessionVariableName);

            // one item
            return $tokens[$service];
        }

        throw new TokenNotFoundException('Token not found in session, are you sure you stored it?');
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        // get previously saved tokens
        $tokens = $this->session->get($this->sessionVariableName);

        if (!is_array($tokens)) {
            $tokens = array();
        }

        $tokens[$service] = $token;

        // save
        $this->session->set($this->sessionVariableName, $tokens);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        // get from session
        $tokens = $this->session->get($this->sessionVariableName);

        return is_array($tokens)
            && isset($tokens[$service])
            && $tokens[$service] instanceof TokenInterface;
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        // get previously saved tokens
        $tokens = $this->session->get($this->sessionVariableName);

        if (is_array($tokens) && array_key_exists($service, $tokens)) {
            unset($tokens[$service]);

            // Replace the stored tokens array
            $this->session->set($this->sessionVariableName, $tokens);
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        $this->session->remove($this->sessionVariableName);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAuthorizationState($service)
    {
        if ($this->hasAuthorizationState($service)) {
            // get from session
            $states = $this->session->get($this->stateVariableName);

            // one item
            return $states[$service];
        }

        throw new AuthorizationStateNotFoundException('State not found in session, are you sure you stored it?');
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        // get previously saved tokens
        $states = $this->session->get($this->stateVariableName);

        if (!is_array($states)) {
            $states = array();
        }

        $states[$service] = $state;

        // save
        $this->session->set($this->stateVariableName, $states);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        // get from session
        $states = $this->session->get($this->stateVariableName);

        return is_array($states)
        && isset($states[$service])
        && null !== $states[$service];
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        // get previously saved tokens
        $states = $this->session->get($this->stateVariableName);

        if (is_array($states) && array_key_exists($service, $states)) {
            unset($states[$service]);

            // Replace the stored tokens array
            $this->session->set($this->stateVariableName, $states);
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        $this->session->remove($this->stateVariableName);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveCodeVerifier($service)
    {
        if ($this->hasCodeVerifier($service)) {
            // get from session
            $verifiers = $this->session->get($this->verifierVariableName);

            // one item
            return $verifiers[$service];
        }

        throw new CodeVerifierNotFoundException('verifier not found in session, are you sure you stored it?');
    }

    /**
     * {@inheritDoc}
     */
    public function storeCodeVerifier($service, $verifier)
    {
        // get previously saved tokens
        $verifiers = $this->session->get($this->verifierVariableName);

        if (!is_array($verifiers)) {
            $verifiers = array();
        }

        $verifiers[$service] = $verifier;

        // save
        $this->session->set($this->verifierVariableName, $verifiers);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasCodeVerifier($service)
    {
        // get from session
        $verifiers = $this->session->get($this->verifierVariableName);

        return is_array($verifiers)
        && isset($verifiers[$service])
        && null !== $verifiers[$service];
    }

    /**
     * {@inheritDoc}
     */
    public function clearCodeVerifier($service)
    {
        // get previously saved tokens
        $verifiers = $this->session->get($this->verifierVariableName);

        if (is_array($verifiers) && array_key_exists($service, $verifiers)) {
            unset($verifiers[$service]);

            // Replace the stored tokens array
            $this->session->set($this->verifierVariableName, $verifiers);
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllCodeVerifiers()
    {
        $this->session->remove($this->verifierVariableName);

        // allow chaining
        return $this;
    }

    /**
     * @return Session
     */
    public function getSession()
    {
        return $this->session;
    }
}
