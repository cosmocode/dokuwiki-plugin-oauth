<?php
/**
 * english language file for oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */


$lang['info']            = 'Redirect URI to use when configuring the applications';
$lang['custom-redirectURI'] = 'Use the following custom redirect URI';
$lang['auth0-key']       = 'The Client ID of your registered <a href="https://manage.auth0.com/#/applications">Auth0 application</a>';
$lang['auth0-secret']    = 'The Client Secret of your registered <a href="https://manage.auth0.com/#/applications">Auth0 application</a>';
$lang['auth0-domain']    = 'The Domain of your registered <a href="https://manage.auth0.com/#/applications">Auth0 account</a>';
$lang['facebook-key']    = 'The App ID of your registered <a href="https://developers.facebook.com/apps">Facebook application</a>';
$lang['facebook-secret'] = 'The App Secret of your registered <a href="https://developers.facebook.com/apps">Facebook application</a>';
$lang['github-key']      = 'The Client ID of your registered <a href="https://github.com/settings/applications">Github application</a>';
$lang['github-secret']   = 'The Client Secret of your registered <a href="https://github.com/settings/applications">Github application</a>';
$lang['gitlab-name']     = 'The displayed text of the login Gitlab button';
$lang['gitlab-url']      = 'The base URL of you Gitlab instance (if self-hosted). Example: https://my.gilab.tld';
$lang['gitlab-key']      = 'The Client ID of your registered <a href="https://gitlab.com/-/profile/applications">Gilab application</a>';
$lang['gitlab-secret']   = 'The Client Secret of your registered <a href="https://gitlab.com/-/profile/applications">Gitlab application</a>';
$lang['gitlab-rules']    = 'Optionnals new-line separated rules that must match the Gitlab user. Rules check if a key exist or a condition match user, groups, or projects data<br>Examples:<br>user/can_create_project<br>user/external = 0<br>user/job_title != intern<br>groups/geeks<br>groups/comm = <br>projects/wargame';
$lang['google-key']      = 'The Client ID of your registered <a href="https://console.developers.google.com/project">Google Project</a> (see Credentials Screen)';
$lang['google-secret']   = 'The Client Secret of your registered <a href="https://console.developers.google.com/project">Google Project</a> (see Credentials Screen)';
$lang['dataporten-key']  = 'The Client ID of your registered <a href="https://dashboard.dataporten.no">Dataporten application</a>';
$lang['dataporten-secret'] = 'The Client Secret of your registered <a href="https://dashboard.dataporten.no">Dataporten application</a>';
$lang['keycloak-key']      = 'The resource id of your Keycloak application.';
$lang['keycloak-secret']   = 'The Secret of your Keycloak Application.';
$lang['keycloak-authurl']  = 'The authorization endpoint URL of your Keycloak setup.';
$lang['keycloak-tokenurl'] = 'The access token endpoint URL of your Keycloak setup.';
$lang['keycloak-userinfourl'] = 'The userinfo endpoint URL of your Keycloak setup.';
$lang['mailRestriction']   = "Limit authentification to users from this domain (optional, must start with an <code>@</code>)";
$lang['yahoo-key']       = 'The Consumer Key of your registered <a href="https://developer.apps.yahoo.com/dashboard/createKey.html">Yahoo Application</a>';
$lang['yahoo-secret']    = 'The Consumer Secret of your registered <a href="https://developer.apps.yahoo.com/dashboard/createKey.html">Yahoo Application</a>';
$lang['doorkeeper-key']      = '(Example) The Application ID of your registered Doorkeeper Application.';
$lang['doorkeeper-secret']   = '(Example) The Secret of your registered Doorkeeper Application.';
$lang['doorkeeper-authurl']  = '(Example) The authorization endpoint URL of your Doorkeeper setup.';
$lang['doorkeeper-tokenurl'] = '(Example) The access token endpoint URL of your Doorkeeper setup.';
$lang['singleService']            = 'Login with single oAuth service only (disables local logins!)';
$lang['singleService_o_'] = 'Allow all services';
$lang['register-on-auth'] = 'Register authenticated users even if self-registration is disabled in main configuration';
