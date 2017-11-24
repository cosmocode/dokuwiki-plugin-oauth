<?php

namespace OAuth\Plugin;

class GitlabAdapter extends AbstractGenericAdapter {
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
        $result = $JSON->decode($this->oAuth->request($this->getUrl() . '/api/v3/user'));

        $data['user'] = $result['username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }

    public function getAuthEndpoint() {
      return ($this->getUrl() . '/oauth/authorize');
    }

    public function getTokenEndpoint() {
      return ($this->getUrl() . '/oauth/token');
    }

    protected function getUrl() {
      return $this->hlp->getUrl($this->getAdapterName());
    }
}
