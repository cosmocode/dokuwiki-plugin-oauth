<?php
/**
 * english language file for oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */


$lang['info']            = 'Redirect URI to use when configuring the applications';
$lang['custom-redirectURI'] = 'Use the following custom redirect URI';
$lang['mailRestriction']   = "Limit authentification to users from this domain (optional, must start with an <code>@</code>)";
$lang['singleService']    = 'Auto redirect to single oAuth service instead of showing login form (does not technically disable local logins. See denyLocal)';
$lang['singleService_o_'] = 'Allow all services';
$lang['hideLocal'] 	      = 'Hide local login form and only show available services';
$lang['denyLocal'] 	      = 'Disable local logins completely';
$lang['register-on-auth'] = 'Register authenticated users even if self-registration is disabled in main configuration';
$lang['overwrite-groups'] = 'Overwrite all DokuWiki user groups by those supplied by provider';
