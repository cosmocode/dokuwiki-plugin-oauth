<?php

namespace dokuwiki\plugin\oauth;

use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Token\TokenInterface;

/**
 * Implements custom handling for storing tokens
 */
class Storage implements TokenStorageInterface
{
    /** @var string */
    protected $storageId;

    /**
     * @param string $storageId The ID identifying the user
     */
    public function __construct($storageId)
    {
        $this->storageId = $storageId;
    }

    /**
     * The path to the file where tokens for this service and user are stored
     *
     * @param string $service
     * @return string
     */
    protected function getServiceFile($service)
    {
        return getCacheName($this->storageId . $service, '.oauth');
    }

    /**
     * Load the data from disk
     *
     * @param string $service
     * @return array
     */
    protected function loadServiceFile($service)
    {
        $file = $this->getServiceFile($service);
        if (file_exists($file)) {
            return unserialize(io_readFile($file, false));
        } else {
            return [];
        }
    }

    /**
     * Store the data to disk
     *
     * @param string $service
     * @param array $data
     */
    protected function saveServiceFile($service, $data)
    {
        $file = $this->getServiceFile($service);
        io_saveFile($file, serialize($data));
    }

    /** @inheritDoc */
    public function retrieveAccessToken($service)
    {
        $data = $this->loadServiceFile($service);
        if (!isset($data['token'])) {
            throw new TokenNotFoundException('No token found in storage');
        }
        return $data['token'];
    }

    /** @inheritDoc */
    public function storeAccessToken($service, TokenInterface $token)
    {
        $data = $this->loadServiceFile($service);
        $data['token'] = $token;
        $this->saveServiceFile($service, $data);
    }

    /** @inheritDoc */
    public function hasAccessToken($service)
    {
        $data = $this->loadServiceFile($service);
        return isset($data['token']);
    }

    /** @inheritDoc */
    public function clearToken($service)
    {
        $data = $this->loadServiceFile($service);
        if (isset($data['token'])) unset($data['token']);
        $this->saveServiceFile($service, $data);

        return $this;
    }

    /** @inheritDoc */
    public function clearAllTokens()
    {
        // TODO: Implement clearAllTokens() method.
        return $this;
    }

    /** @inheritDoc */
    public function storeAuthorizationState($service, $state)
    {
        $data = $this->loadServiceFile($service);
        $data['state'] = $state;
        $this->saveServiceFile($service, $data);
        return $this;
    }

    /** @inheritDoc */
    public function hasAuthorizationState($service)
    {
        $data = $this->loadServiceFile($service);
        return isset($data['state']);
    }

    /**
     * @inheritDoc
     * @throws TokenNotFoundException
     */
    public function retrieveAuthorizationState($service)
    {
        $data = $this->loadServiceFile($service);
        if (!isset($data['state'])) {
            throw new TokenNotFoundException('No state found in storage');
        }
        return $data['state'];
    }

    /** @inheritDoc */
    public function clearAuthorizationState($service)
    {
        $data = $this->loadServiceFile($service);
        if (isset($data['state'])) unset($data['state']);
        $this->saveServiceFile($service, $data);

        return $this;
    }

    /** @inheritDoc */
    public function clearAllAuthorizationStates()
    {
        // TODO: Implement clearAllAuthorizationStates() method.

        return $this;
    }
}
