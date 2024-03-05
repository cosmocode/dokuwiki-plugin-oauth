<?php

namespace dokuwiki\plugin\oauth;

use dokuwiki\plugin\config\core\Setting\Setting;

/**
 * Custom Setting to display the default redirect URL
 */
class RedirectSetting extends Setting
{
    /** @inheritdoc  */
    public function update($input)
    {
        return true;
    }


    /** @inheritdoc  */
    public function html(\admin_plugin_config $plugin, $echo = false)
    {
        /** @var \helper_plugin_oauth $hlp */
        $hlp = plugin_load('helper', 'oauth');

        $key   = htmlspecialchars($this->key);
        $value = '<code>' . $hlp->redirectURI() . '</code>';

        $label = '<label for="config___' . $key . '">' . $this->prompt($plugin) . '</label>';
        $input = '<div>' . $value . '</div>';
        return [$label, $input];
    }
}
