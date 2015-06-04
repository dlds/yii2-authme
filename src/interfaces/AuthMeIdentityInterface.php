<?php

namespace dlds\authme\interfaces;

interface AuthMeIdentityInterface {

    /**
     * Retreives identity primary key used for authorization
     * @return string secondary authorization key
     */
    public function getPrimaryKey();

    /**
     * Retreives identity secondary key used for authorization
     * @return string secondary authorization key
     */
    public function getSecondaryKey();
}