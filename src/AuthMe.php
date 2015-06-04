<?php

namespace dlds\shareit;

use Yii;
use yii\helpers\ArrayHelper;
use yii\helpers\Html;
use dlds\shareit\ShareItAssets;

class AuthMe extends \yii\base\Widget {

    /**
     * @var string secret key for encrypting/decrypting tokens
     */
    public $secret;

    public function loginByAccessToken($token)
    {
        $identity = AccessTokenHelper::getIdentity($token);

        if ($identity)
        {
            \Yii::$app->user->login($identity);
        }
    }

    public static function getToken(UsrIdentity $user)
    {
        Yii::$app->getSecurity()->encryptByPassword(self::getTokenContent($user));
    }

    private static function getTokenContent($user)
    {
        return sprintf('%s-%s-%s', $user->primaryKey, $user->auth_key, time());
    }
}