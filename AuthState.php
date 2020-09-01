<?php

namespace dokuwiki\plugin\oauth;

class AuthState
{
    /**
     * @var string
     */
    protected $service;

    /**
     * @var string
     */
    protected $id;

    /**
     * @var bool
     */
    protected $inProgress;

    /**
     * @var array
     */
    protected $loginParams;

    /**
     * @var string
     */
    protected $user;

    /**
     * @var string
     */
    protected $pass;

    /**
     * @var string
     */
    protected $browserId;

    /**
     * @var int
     */
    protected $time;

    /**
     * @var string
     */
    protected $do;

    /**
     * @var array
     */
    protected $request;

    /**
     * @var int
     */
    protected $rev;

    /**
     * @return string
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * @param string $service
     */
    public function setService($service)
    {
        $this->service = $service;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $id
     */
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * @return bool
     */
    public function isInProgress()
    {
        return $this->inProgress;
    }

    /**
     * @param bool $inProgress
     */
    public function setInProgress($inProgress)
    {
        $this->inProgress = $inProgress;
    }

    /**
     * @return array
     */
    public function getLoginParams()
    {
        return $this->loginParams;
    }

    /**
     * @param array $loginParams
     */
    public function setLoginParams($loginParams)
    {
        $this->loginParams = $loginParams;
    }

    /**
     * @return string
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * @param string $user
     */
    public function setUser($user)
    {
        $this->user = $user;
    }

    /**
     * @return string
     */
    public function getPass()
    {
        return $this->pass;
    }

    /**
     * @param string $pass
     */
    public function setPass($pass)
    {
        $this->pass = $pass;
    }

    /**
     * @return string
     */
    public function getBrowserId()
    {
        return $this->browserId;
    }

    /**
     * @param string $browserId
     */
    public function setBrowserId($browserId)
    {
        $this->browserId = $browserId;
    }

    /**
     * @return int
     */
    public function getTime()
    {
        return $this->time;
    }

    /**
     * @param int $time
     */
    public function setTime($time)
    {
        $this->time = $time;
    }

    /**
     * @return string
     */
    public function getDo()
    {
        return $this->do;
    }

    /**
     * @param string $do
     */
    public function setDo($do)
    {
        $this->do = $do;
    }

    /**
     * @return array
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param array $request
     */
    public function setRequest($request)
    {
        $this->request = $request;
    }

    /**
     * @return int
     */
    public function getRev()
    {
        return $this->rev;
    }

    /**
     * @param int $rev
     */
    public function setRev($rev)
    {
        $this->rev = $rev;
    }
}
