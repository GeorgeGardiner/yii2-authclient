<?php
/***
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
 * structure that represents a cryptographic key.
 */

namespace yii\authclient\jose;

use yii\base\Exception;
use yii\base\Object;
use yii\helpers\Json;

class Jwk extends Jose {

    private $_key = null;

    public function getKey()
    {
        if($this->_key == null) {
            throw new Exception('Key has not been set');
        }
        else {
            return $this->_key;
        }
    }

    public function setKey($key) {
        if(!isset($key['kty'])) {
            throw new Exception('Key is invalid');
        }
        else {
            $this->_key = $key;
        }
    }
}
