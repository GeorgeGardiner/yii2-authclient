<?php
/***
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
 * structure that represents a cryptographic key.
 */

namespace yii\authclient\jose;

use yii\base\Exception;
use yii\base\Object;
use yii\helpers\Json;

class Jose {

    private $_header;

    protected function b64uEncode($input) {
        $base64url = strtr($input, '-_,', '+/=');
        $base64 = base64_decode($base64url);
        return $base64;
    }

    protected function b64uDecode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    protected function unpackJson($input)
    {
        return Json::decode($this->b64uDecode($input));
    }

    protected function packJson($input)
    {
        return $this->b64uEncode(Json::encode($input, true));
    }

    public function getHeader()
    {
        if($this->_header === null) {
            throw new Exception('Header has not been set');
        }
        return $this->_header;
    }

    public function setHeader($header)
    {
        $this->_header = $header;
    }

}
