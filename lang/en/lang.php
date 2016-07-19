<?php
/**
 * English language file for oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['emailduplicate'] = 'This email is already associated with another user.';
$lang['loginwith']      = 'Login with other Services:';
$lang['authnotenabled'] = 'The account associated with your email address has not enabled logging in with %s. Please login by other means and enable it in your profile.';
$lang['wrongConfig'] = 'The oAuth plugin has been malconfigured. Defaulting to local authentication only. Please contact your wiki administrator.';
$lang['loginButton'] = 'Login with ';//... i.e. Google (on SingleAuth)
$lang['rejectedEMail'] = 'Invalid eMail-Account used. Only email accounts from the following domain(s) are allowed: %s!';
$lang['eMailRestricted'] = '<p id="oauth_email_restricted">Only email accounts from the following domain(s) are allowed: %s</p>';
$lang['addUser not possible'] = 'Self-Registration is currently disabled or conf/users.auth.php is not writable. Please ask your DokuWiki administrator to create your account manually.';
$lang['oauth login failed'] = 'Your (re)login has failed.';
