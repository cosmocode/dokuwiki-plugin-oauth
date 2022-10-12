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
class MergeGroupsTest extends DokuWikiTest
{

    protected $pluginsEnabled = ['oauth'];

    /**
     * @see testMergeGroups
     */
    public function provideTestData()
    {
        return [
            [
                ['hello', 'provider1', 'service', 'user'],
                ['provider1', 'provider2'],
                ['service', 'service2'],
                false,
                ['hello', 'provider1', 'provider2', 'service', 'user']
            ],
            [
                ['hello', 'provider1', 'service', 'user'],
                ['provider1', 'provider2'],
                ['service', 'service2'],
                true,
                ['provider1', 'provider2', 'service', 'user']
            ],
            [
                ['hello', 'provider1', 'service', 'user'],
                [],
                ['service', 'service2'],
                false,
                ['hello', 'provider1', 'service', 'user']
            ],
            [
                ['hello', 'provider1', 'service', 'user'],
                [],
                ['service', 'service2'],
                true,
                ['service', 'user']
            ]
        ];
    }

    /**
     * @dataProvider provideTestData
     */
    public function testMergeGroups($localGroups, $providerGroups, $services, $overwrite, $expect)
    {
        $oauthMgr = new OAuthManager();
        $result = $this->callInaccessibleMethod(
            $oauthMgr, 'mergeGroups',
            [$localGroups, $providerGroups, $services, $overwrite]
        );
        sort($expect);
        sort($result);

        $this->assertEquals($expect, $result);
    }

}
