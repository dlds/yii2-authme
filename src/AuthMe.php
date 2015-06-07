<?php

namespace dlds\authme;

use Yii;
use dlds\authme\components\AuthMeToken;

class AuthMe extends \yii\base\Component {

    /**
     * @var string secret key for encrypting/decrypting tokens
     */
    public $secret;

    /**
     * @var int token expiration time
     */
    public $tokenExpiry;

    /**
     * Authenticate user by given token and log him in
     * @param string $token
     */
    public function loginByAccessToken($token)
    {
        $identity = $this->getIdentity($token);

        if ($identity)
        {
            \Yii::$app->user->login($identity);
        }
    }

    /**
     * Retreives identity based on given token
     * - parses given token and find appropriate identity
     * - validate if timestamp in token is valid
     * @param string $string
     * @return interfaces\AuthMeIdentityInterface identity
     */
    public function getIdentity($string)
    {
        $token = AuthMeToken::initFromString($string, $this->secret, $this->tokenExpiry);

        if ($token && !$token->isExpired())
        {
            $identityClass = \Yii::$app->user->identityClass;

            $identity = $identityClass::findOne($token->getPrimaryKey());

            if ($identity && $token->isValid($identity->getSecondaryKey()))
            {
                return $identity;
            }
        }

        return false;
    }

    /**
     * Retrieves authorization token for given identity
     * @param AuthMeIdentityInterface $user
     * @return string authorization token
     */
    public function getToken(interfaces\AuthMeIdentityInterface $identity)
    {
        $token = AuthMeToken::initFromIdentity($identity);

        return $token->asString($this->secret);
    }
}