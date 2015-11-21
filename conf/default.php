<?php
/**
 * Default settings for the oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$conf['custom-redirectURI']  = '';
$conf['facebook-key']        = '';
$conf['facebook-secret']     = '';
$conf['github-key']          = '';
$conf['github-secret']       = '';
$conf['google-key']          = '';
$conf['google-secret']       = '';
$conf['yahoo-key']           = '';
$conf['yahoo-secret']        = '';
$conf['doorkeeper-key']      = '';
$conf['doorkeeper-secret']   = '';
$conf['doorkeeper-authurl']  = 'https://doorkeeper-provider.herokuapp.com/oauth/authorize';
$conf['doorkeeper-tokenurl'] = 'https://doorkeeper-provider.herokuapp.com/oauth/token';
$conf['mailRestriction']     = '';
$conf['singleService']       = '';
$conf['yahoogeneric-key']               = '';
$conf['yahoogeneric-secret']            = '';
$conf['yahoogeneric-requesttokenurl']   = 'https://api.login.yahoo.com/oauth/v2/get_request_token';
$conf['yahoogeneric-tokenurl']          = 'https://api.login.yahoo.com/oauth/v2/get_token';
$conf['yahoogeneric-authurl']           = 'https://api.login.yahoo.com/oauth/v2/request_auth';
