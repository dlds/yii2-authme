<?php

namespace dlds\authme;

interface AuthIdentityInterface {

    /**
     * Retreives identity auth key
     * @return string authorization key
     */
    public function getAuthKey();
}