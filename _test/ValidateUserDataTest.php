<?php

namespace dokuwiki\plugin\oauth\test;

use dokuwiki\plugin\oauth\Exception;
use dokuwiki\plugin\oauth\OAuthManager;
use DokuWikiTest;

/**
 * user data validation tests for the oauth plugin
 *
 * @group plugin_oauth
 * @group plugins
 */
class ValidateUserDataTest extends DokuWikiTest
{

    protected $pluginsEnabled = ['oauth'];

    /**
     * @see testValidateUserData
     */
    public function provideUserData()
    {
        return [
            [
                ['mail' => 'test@ExamPLe.com'],
                ['user' => 'test', 'name' => 'test', 'mail' => 'test@example.com', 'grps' => []],
            ],
            [
                ['user' => 'tuser', 'mail' => 'test@example.com', 'grps' => ['one grp', 'Two']],
                ['user' => 'tuser', 'name' => 'tuser', 'mail' => 'test@example.com', 'grps' => ['one_grp', 'two']],
            ],
            [
                ['user' => 'TEST', 'name' => 'Test User', 'mail' => 'test@example.com', 'grps' => ['one', 'two']],
                ['user' => 'test', 'name' => 'Test User', 'mail' => 'test@example.com', 'grps' => ['one', 'two']],
            ],
        ];
    }

    /**
     * @dataProvider provideUserData
     */
    public function testValidateUserData($input, $expect)
    {
        $oauthMgr = new OAuthManager();
        $result = $this->callInaccessibleMethod($oauthMgr, 'validateUserData', [$input, 'service']);
        $this->assertEquals($expect, $result);
    }

    public function testMissingMail()
    {
        $this->expectException(Exception::class);

        $input = [
            'user' => 'test',
            'name' => 'Test USer',
        ];
        $oauthMgr = new OAuthManager();
        $this->callInaccessibleMethod($oauthMgr, 'validateUserData', [$input, 'service']);
    }
}
