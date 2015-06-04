<?php

namespace dlds\authme;

use Yii;

class AuthMe extends \yii\base\Component {

    /**
     * @var string secret key for encrypting/decrypting tokens
     */
    public $secret;

    public function loginByAccessToken($token)
    {
        $identity = $this->getIdentity($token);

        if ($identity)
        {
            \Yii::$app->user->login($identity);
        }
    }

    public static function getIdentity($token)
    {
        return Yii::$app->getSecurity()->encryptByPassword(self::getTokenContent($user));
    }

    public static function getToken($user)
    {
        Yii::$app->getSecurity()->encryptByPassword(self::getTokenContent($user));
    }

    private static function getTokenContent($user)
    {
        return sprintf('%s-%s-%s', $user->primaryKey, $user->auth_key, time());
    }
}