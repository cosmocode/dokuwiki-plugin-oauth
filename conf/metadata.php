<?php
/**
 * Options for the oauth plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

/** @var helper_plugin_oauth $helper */
$helper = plugin_load('helper', 'oauth');
foreach($helper->listServices() as $service) {
    $service = strtolower($service);
    $meta["$service-key"]    = array('string');
    $meta["$service-secret"] = array('string');
}
