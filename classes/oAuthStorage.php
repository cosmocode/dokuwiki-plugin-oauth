<?php

namespace OAuth\Plugin;

use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Token\TokenInterface;

/**
 * Class oAuthHTTPClient
 *
 * Implements the client interface using DokuWiki's HTTPClient
 */
class oAuthStorage implements TokenStorageInterface {

    /**
     * The path to the file where tokens for this service are stored
     *
     * @param string $service
     * @return string
     */
    protected function getServiceFile($service) {
        return getCacheName($service, '.oauth');
    }

    /**
     * Load the data from disk
     *
     * @param string $service
     * @return array
     */
    protected function loadServiceFile($service) {
        $file = $this->getServiceFile($service);
        if(file_exists($file)) {
            return unserialize(io_readFile($file, false));
        } else {
            return array();
        }
    }

    /**
     * Store the data to disk
     *
     * @param string $service
     * @param array  $data
     */
    protected function saveServiceFile($service, $data) {
        $file = $this->getServiceFile($service);
        io_saveFile($file, serialize($data));
    }

    /**
     * @param string $service
     *
     * @return TokenInterface
     *
     * @throws TokenNotFoundException
     */
    public function retrieveAccessToken($service) {
        $data = $this->loadServiceFile($service);
        if(!isset($data['token'])) {
            throw new TokenNotFoundException('No token found in storage');
        }
        return $data['token'];
    }

    /**
     * @param string         $service
     * @param TokenInterface $token
     *
     * @return TokenStorageInterface
     */
    public function storeAccessToken($service, TokenInterface $token) {
        $data          = $this->loadServiceFile($service);
        $data['token'] = $token;
        $this->saveServiceFile($service, $data);
    }

    /**
     * @param string $service
     *
     * @return bool
     */
    public function hasAccessToken($service) {
        $data = $this->loadServiceFile($service);
        return isset($data['token']);
    }

    /**
     * Delete the users token. Aka, log out.
     *
     * @param string $service
     *
     * @return TokenStorageInterface
     */
    public function clearToken($service) {
        $data = $this->loadServiceFile($service);
        if(isset($data['token'])) unset($data['token']);
        $this->saveServiceFile($service, $data);
    }

    /**
     * Delete *ALL* user tokens. Use with care. Most of the time you will likely
     * want to use clearToken() instead.
     *
     * @return TokenStorageInterface
     */
    public function clearAllTokens() {
        // TODO: Implement clearAllTokens() method.
    }

    /**
     * Store the authorization state related to a given service
     *
     * @param string $service
     * @param string $state
     *
     * @return TokenStorageInterface
     */
    public function storeAuthorizationState($service, $state) {
        $data          = $this->loadServiceFile($service);
        $data['state'] = $state;
        $this->saveServiceFile($service, $data);
    }

    /**
     * Check if an authorization state for a given service exists
     *
     * @param string $service
     *
     * @return bool
     */
    public function hasAuthorizationState($service) {
        $data = $this->loadServiceFile($service);
        return isset($data['state']);
    }

    /**
     * Retrieve the authorization state for a given service
     *
     * @param string $service
     *
     * @throws \OAuth\Common\Storage\Exception\TokenNotFoundException
     * @return string
     */
    public function retrieveAuthorizationState($service) {
        $data = $this->loadServiceFile($service);
        if(!isset($data['state'])) {
            throw new TokenNotFoundException('No state found in storage');
        }
        return $data['state'];
    }

    /**
     * Clear the authorization state of a given service
     *
     * @param string $service
     *
     * @return TokenStorageInterface
     */
    public function clearAuthorizationState($service) {
        $data          = $this->loadServiceFile($service);
        if(isset($data['state'])) unset($data['state']);
        $this->saveServiceFile($service, $data);
    }

    /**
     * Delete *ALL* user authorization states. Use with care. Most of the time you will likely
     * want to use clearAuthorization() instead.
     *
     * @return TokenStorageInterface
     */
    public function clearAllAuthorizationStates() {
        // TODO: Implement clearAllAuthorizationStates() method.
    }
}