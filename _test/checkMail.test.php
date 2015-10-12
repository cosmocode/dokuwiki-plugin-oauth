<?php
/**
 * General tests for the oauth plugin
 *
 * @group plugin_oauth
 * @group plugins
 */
class checkMail_plugin_oauth_test extends DokuWikiTest {

    protected $pluginsEnabled = array('oauth');

    public function test_checkMail_twoDomains() {

        global $conf;
        $conf['plugin']['oauth']['mailRestriction'] = '@foo.org,@example.com';

        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauth');

        $testmail = "bar@foo.org";
        $this->assertTrue($hlp->checkMail($testmail),$testmail);
        $testmail = "bar@example.com";
        $this->assertTrue($hlp->checkMail($testmail), $testmail);
        $testmail = "bar@bar.org";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
    }

    public function test_checkMail_oneDomains() {

        global $conf;
        $conf['plugin']['oauth']['mailRestriction'] = '@foo.org';

        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauth');

        $testmail = "bar@foo.org";
        $this->assertTrue($hlp->checkMail($testmail),$testmail);
        $testmail = "bar@example.com";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
        $testmail = "bar@bar.org";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
    }

}
