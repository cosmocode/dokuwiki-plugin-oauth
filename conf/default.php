<?php
/**
 * Default settings for the oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

/** @var helper_plugin_oauth $helper */
$helper = plugin_load('helper', 'oauth');
foreach($helper->listServices(false) as $service) {
    $service = strtolower($service);
    $conf["$service-key"]    = '';
    $conf["$service-secret"] = '';
}
