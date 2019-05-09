<?php

namespace OAuth\Plugin;

/**
 * Class GenericAdapter
 *
 * Adapter for making DokuWiki login against a Generic Oauth
 * provider. The used Generic Service backend expects the authorization and
 * token endpoints to be configured in the DokuWiki backend.
 * Field mappings and User info URLs are also configured in the DokuWiki backend.
 */
class GenericAdapter extends AbstractAdapter {


    protected function getFieldMap($mapping)
    {
        $result = array();
        if ($mapping !== '') {
            $fields = explode(" ", $mapping);
            foreach ($fields as $line) {
                list($key, $val) = explode('=', $line);
                $result[$key] = $val;
            }
        }
        return $result;
    }

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        /** var OAuth\OAuth2\Service\Generic $this->oAuth */
        $userinfourl = $this->hlp->getUserInfoEndpoint('Generic');
        if(!$userinfourl) {
            msg("Please define generic-userinfourl in settings.", -1);
            return false;
        }
        $result = $JSON->decode($this->oAuth->request($userinfourl));

        $fieldmap = $this->getFieldMap($this->hlp->getConf('generic-fieldmap'));
        foreach($fieldmap as $key => $value) {
            $data[$key] = $result[$value];
        }

        return $data;
    }

    /**
     * We make use of the "Generic" oAuth 2 Service as defined in
     * phpoauthlib/src/OAuth/OAuth2/Service/Generic.php
     *
     * @return string
     */
    public function getServiceName() {
        return 'Generic';
    }

}
