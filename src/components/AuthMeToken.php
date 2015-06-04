<?php

namespace dlds\authme\components;

use dlds\authme\interfaces\AuthMeIdentityInterface;
use dlds\authme\generators\HashidGenerator;

class AuthMeToken {

    /**
     * Hash template
     */
    const TOKEN_TEMPLATE = '%s-%s-%s';

    /**
     * @var int expiry time
     */
    public $expiry = 86400;

    /**
     * @var string primary key held in token
     */
    private $_primaryKey;

    /**
     * @var string secondary key held in token
     */
    private $_secondaryKey;

    /**
     * @var int token timestamp
     */
    private $_timestamp;

    /**
     * Private constructor so instance can be created only using one of
     * following factory method
     * @param string $primaryKey
     * @param string $secondaryKey
     * @param string $timestamp
     */
    private function __construct($primaryKey, $secondaryKey, $timestamp)
    {
        $this->_primaryKey = $primaryKey;
        $this->_secondaryKey = $secondaryKey;
        $this->_timestamp = $timestamp;
    }

    /**
     * Retrieves primary key
     * @return string primary key
     */
    public function getPrimaryKey()
    {
        return $this->_primaryKey;
    }

    /**
     * Retrieves secondary key
     * @return string primary key
     */
    public function getSecondaryKey()
    {
        return $this->_secondaryKey;
    }

    /**
     * Retrieves hasn of current token
     * @param string $secret secret key used in encrypting
     * @return string token hash
     */
    public function asString($secret)
    {
        $source = sprintf(self::TOKEN_TEMPLATE, $this->_primaryKey, $this->_secondaryKey, $this->_timestamp);

        return $this->_encrypt($source, $secret);
    }

    /**
     * Indicates if token is valid
     */
    public function isValid($secondaryKey)
    {
        return $this->_secondaryKey == $secondaryKey;
    }

    /**
     * Indicates if token is valid
     */
    public function isExpired()
    {
        return (time() - $this->_timestamp) > $this->expiry;
    }

    /**
     * Initializes token from given identity
     * @param AuthMeIdentityInterface $identity
     * @return AuthMeToken new instance
     */
    public static function initFromIdentity(AuthMeIdentityInterface $identity, $time = false)
    {
        if (false === $time)
        {
            $time = time();
        }

        return new self($identity->getPrimaryKey(), $identity->getSecondaryKey(), $time);
    }

    /**
     * Initializes token from given hash
     * @param string $hash
     * @return AuthMeToken new instance
     */
    public static function initFromString($string, $secret)
    {
        $decrypted = self::_decrypt($string, $secret);

        if (preg_match('/^(\d+)\-(.*)\-(\d+)$/', $decrypted, $matches))
        {
            return new self($matches[1], $matches[2], $matches[3]);
        }

        return null;
    }

    /**
     * Encrypts given string using secret key
     * @param string $text input string
     * @param string $secret secret key
     * @return string encrypted
     */
    private static function _encrypt($text, $secret)
    {
        return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $secret, $text, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));
    }

    /**
     * Decrypts given string using secret key
     * @param string $text input string
     * @param string $secret secret key
     * @return string decrypted string
     */
    private static function _decrypt($text, $secret)
    {
        // Decrypt $string
        return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $secret, base64_decode($text), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
    }
}