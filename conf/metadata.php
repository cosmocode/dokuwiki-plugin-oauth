<?php
/**
 * Options for the oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

class setting_plugin_oauth extends setting {

    function update($input) {
        return true;
    }

    public function html(&$plugin, $echo = false) {
        /** @var helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        $key   = htmlspecialchars($this->_key);
        $value = '<code>'.$hlp->redirectURI().'</code>';

        $label = '<label for="config___'.$key.'">'.$this->prompt($plugin).'</label>';
        $input = '<div>'.$value.'</div>';
        return array($label, $input);
    }

}

$meta['info']                = array('plugin_oauth');
$meta['auth0-key']           = array('string');
$meta['auth0-secret']        = array('string');
$meta['auth0-domain']        = array('string');
$meta['custom-redirectURI']  = array('string','_caution' => 'warning');
$meta['facebook-key']        = array('string');
$meta['facebook-secret']     = array('string');
$meta['github-key']          = array('string');
$meta['github-secret']       = array('string');
$meta['google-key']          = array('string');
$meta['google-secret']       = array('string');
$meta['dataporten-key']      = array('string');
$meta['dataporten-secret']   = array('string');
$meta['keycloak-key']        = array('string');
$meta['keycloak-secret']     = array('string');
$meta['keycloak-authurl']    = array('string');
$meta['keycloak-tokenurl']   = array('string');
$meta['keycloak-userinfourl'] = array('string');
$meta['yahoo-key']           = array('string');
$meta['yahoo-secret']        = array('string');
$meta['doorkeeper-key']      = array('string');
$meta['doorkeeper-secret']   = array('string');
$meta['doorkeeper-authurl']  = array('string');
$meta['doorkeeper-tokenurl'] = array('string');
$meta['mailRestriction']     = array('string','_pattern' => '!^(@[^,@]+(\.[^,@]+)+(,|$))*$!'); // https://regex101.com/r/mG4aL5/3
$meta['singleService']       = array('multichoice',
                                     '_choices' => array(
                                         '',
                                         'Auth0',
                                         'Google',
                                         'Dataporten',
                                         'Facebook',
                                         'Github',
                                         'Yahoo',
                                         'Doorkeeper',
                                         'Keycloak'));
