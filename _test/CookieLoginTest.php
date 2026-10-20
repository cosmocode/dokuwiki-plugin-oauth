<?php

namespace dokuwiki\plugin\oauth\test;

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauth\OAuthManager;
use dokuwiki\plugin\oauth\Session;
use DokuWikiTest;

/**
 * Login and logout via the persistent cookie must only work with a cookie we issued
 *
 * @group plugin_oauth
 * @group plugins
 */
class CookieLoginTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['oauth'];

    /** @var string storageId of the user the forged cookies try to log in as */
    protected $victim;

    public function setUp(): void
    {
        parent::setUp();
        $this->victim = md5('victim@example.com');
    }

    public function tearDown(): void
    {
        unset($_COOKIE[DOKU_COOKIE]);
        parent::tearDown();
    }

    /**
     * Manager with a fake service whose token handling must not be reached for invalid cookies
     *
     * @param bool $expectTrusted whether the cookie is expected to be accepted
     * @param bool $expectLogout whether the service logout is expected to be called
     * @return OAuthManager
     */
    protected function getManager($expectTrusted, $expectLogout = false)
    {
        $adapter = $this->createMock(Adapter::class);
        if ($expectTrusted) {
            $adapter->method('getUser')->willThrowException(new \RuntimeException('token used'));
            $adapter->expects($expectLogout ? $this->once() : $this->never())->method('logout');
        } else {
            $adapter->expects($this->never())->method('initOAuthService');
            $adapter->expects($this->never())->method('refreshOutdatedToken');
            $adapter->expects($this->never())->method('getUser');
            $adapter->expects($this->never())->method('logout');
        }

        return new class ($adapter) extends OAuthManager {
            protected $adapter;

            public function __construct($adapter)
            {
                $this->adapter = $adapter;
            }

            protected function loadService($servicename)
            {
                return $this->adapter;
            }

            public function cookieLogin()
            {
                return $this->loginByCookie();
            }
        };
    }

    /**
     * Cookie as written by versions before the fix: computable from the user's email address
     */
    public function testForgedLegacyCookie()
    {
        $_COOKIE[DOKU_COOKIE] = 'test|oauth|' . $this->victim;
        $this->assertFalse($this->getManager(false)->cookieLogin());
    }

    public function testWrongSignature()
    {
        $expires = time() + 60;
        $_COOKIE[DOKU_COOKIE] = "test|oauth|{$this->victim}|$expires|" . str_repeat('0', 64);
        $this->assertFalse($this->getManager(false)->cookieLogin());
    }

    public function testSignatureOfOtherUser()
    {
        $expires = time() + 60;
        $own = Session::getInstance()->buildCookie('test', md5('attacker@example.com'), $expires);
        $mac = substr($own, strrpos($own, '|') + 1);
        $_COOKIE[DOKU_COOKIE] = "test|oauth|{$this->victim}|$expires|$mac";
        $this->assertFalse($this->getManager(false)->cookieLogin());
    }

    public function testExpired()
    {
        $_COOKIE[DOKU_COOKIE] = Session::getInstance()->buildCookie('test', $this->victim, time() - 1);
        $this->assertFalse($this->getManager(false)->cookieLogin());
    }

    public function testValid()
    {
        $_COOKIE[DOKU_COOKIE] = Session::getInstance()->buildCookie('test', $this->victim, time() + 60);
        $this->expectExceptionMessage('token used');
        $this->getManager(true)->cookieLogin();
    }

    public function testForgedLogout()
    {
        $_COOKIE[DOKU_COOKIE] = 'test|oauth|' . $this->victim;
        $this->getManager(false)->logout();
        $this->addToAssertionCount(1); // expectations on the mock
    }

    public function testValidLogout()
    {
        $_COOKIE[DOKU_COOKIE] = Session::getInstance()->buildCookie('test', $this->victim, time() + 60);
        $this->getManager(true, true)->logout();
        $this->addToAssertionCount(1); // expectations on the mock
    }

    /**
     * Rejected oauth cookies must not reach core's auth_login(), which would try to decrypt them
     *
     * @return array[]
     */
    public function provideInvalidCookies()
    {
        $victim = md5('victim@example.com');
        return [
            'legacy' => ["test|oauth|$victim"],
            'wrong signature' => ["test|oauth|$victim|" . (time() + 60) . '|' . str_repeat('0', 64)],
            'expired' => [null],
        ];
    }

    /**
     * @dataProvider provideInvalidCookies
     */
    public function testInvalidCookieIsRemoved($cookie)
    {
        $_COOKIE[DOKU_COOKIE] = $cookie ?? Session::getInstance()->buildCookie('test', $this->victim, time() - 1);
        $this->assertFalse(Session::getInstance()->getCookie());
        $this->assertSame([null, null, null], auth_getCookie());
    }

    public function testValidCookieIsKept()
    {
        $cookie = Session::getInstance()->buildCookie('test', $this->victim, time() + 60);
        $_COOKIE[DOKU_COOKIE] = $cookie;
        $this->assertNotFalse(Session::getInstance()->getCookie());
        $this->assertSame($cookie, $_COOKIE[DOKU_COOKIE]);
    }

    public function testCoreCookieIsKept()
    {
        $_COOKIE[DOKU_COOKIE] = base64_encode('user') . '|1|' . base64_encode('crypted');
        $this->assertFalse(Session::getInstance()->getCookie());
        $this->assertSame('user', auth_getCookie()[0]);
    }
}
