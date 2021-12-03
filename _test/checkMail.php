<?php

namespace dokuwiki\plugin\oauth\test;

use DokuWikiTest;

/**
 * Mail Restriction tests for the oauth plugin
 *
 * @group plugin_oauth
 * @group plugins
 */
class CheckMailTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['oauth'];

    /**
     * @return array[]
     * @see testCheckMail
     */
    public function provideCheckMailData()
    {
        return [
            ['@foo.org,@example.com', 'bar@foo.org', true],
            ['@foo.org,@example.com', 'bar@example.com', true],
            ['@foo.org,@example.com', 'bar@bar.org', false],
            ['@foo.org', 'bar@foo.org', true],
            ['@foo.org', 'bar@example.com', false],
            ['@foo.org', 'bar@bar.org', false],

        ];
    }

    /**
     * @dataProvider provideCheckMailData
     * @param string $restriction
     * @param string $input
     * @param string $expected
     * @return void
     */
    public function testCheckMail($restriction, $input, $expected)
    {
        global $conf;
        $conf['plugin']['oauth']['mailRestriction'] = $restriction;

        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');
        $this->assertSame($expected, $hlp->checkMail($input));
    }
}
