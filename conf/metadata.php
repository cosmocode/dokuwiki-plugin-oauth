<?php

/**
 * Options for the oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['info']                = array(\dokuwiki\plugin\oauth\RedirectSetting::class);
$meta['custom-redirectURI']  = array('string','_caution' => 'warning');
// https://regex101.com/r/mG4aL5/3
$meta['mailRestriction']     = array('string','_pattern' => '!^(@[^,@]+(\.[^,@]+)+(,|$))*$!');
$meta['mailEnforcement']     = array('string','_pattern' => '!^(@[^,@]+(\.[^,@]+)+(,|$))*$!');
$meta['singleService']       = array('onoff');
$meta['register-on-auth']    = array('onoff','_caution' => 'security');
$meta['overwrite-groups']    = array('onoff','_caution' => 'danger');
