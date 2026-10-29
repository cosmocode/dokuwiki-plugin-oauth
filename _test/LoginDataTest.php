<?php

namespace dokuwiki\plugin\oauth\test;

use dokuwiki\plugin\oauth\OAuthManager;
use dokuwiki\plugin\oauth\Session;
use DokuWikiTest;

/**
 * The login data of a running oAuth flow must stay in the session until the service redirects back
 *
 * @group plugin_oauth
 * @group plugins
 */
class LoginDataTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['oauth'];

    /**
     * A parallel request of a user who is not logged in must not remove the login data
     */
    public function testParallelRequestKeepsLoginData()
    {
        $session = Session::getInstance();
        $session->setLoginData('google', 'some:page');

        $manager = new OAuthManager();
        $this->assertFalse($manager->continueFlow());

        $this->assertEquals(
            ['servicename' => 'google', 'id' => 'some:page'],
            $session->getLoginData()
        );
    }
}
