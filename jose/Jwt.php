<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\authclient\jose;

use yii\base\Exception;
use yii\base\Object;
use yii\helpers\Json;

class Jwt extends Jose implements SignableInterface {

    private $_claims = null;
    private $_signature = null;

    public function __construct($raw = null) {
        if($raw !== null) {
            $parts = explode('.', $raw);
            if(count($parts) == 3) {
                $this->setHeader($this->unpackJson($parts[0]));
                $this->setClaims($this->unpackJson($parts[1]));
                $this->setSignature($this->b64uDecode($parts[2]));
            }
            if(count($parts) == 5) {
                throw new Exception('Encrypted tokens are not yet supported');
            }
            throw new Exception('JWT was in an unexpected format');
        }
    }


    public function setClaims($claims)
    {
        $this->_claims = $claims;
    }

    public function getClaims()
    {
        if($this->_claims === null) {
            throw new Exception('No claims set.');
        }
        return $this->_claims;
    }

    public function setSignature($signature)
    {
        $this->_signature = $signature;
    }

    public function getSignature()
    {
        if($this->_signature === null) {
            throw new Exception('No signature set.');
        }
        return $this->_signature;
    }

    public function getPayload()
    {
        return $this->packJson($this->getClaims());
    }

}
