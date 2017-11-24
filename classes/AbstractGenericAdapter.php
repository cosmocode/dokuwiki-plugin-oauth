<?php
namespace OAuth\Plugin;

abstract class AbstractGenericAdapter extends AbstractAdapter {
    /**
    * We make use of the "Generic" oAuth 2 Service as defined in
    * phpoauthlib/src/OAuth/OAuth2/Service/Generic.php
    *
    * @return string
    */
    public function getServiceName() {
        return 'Generic';
    }

    abstract public function getAuthEndpoint();

    abstract public function getTokenEndpoint();
}
