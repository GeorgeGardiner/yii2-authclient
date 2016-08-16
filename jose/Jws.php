<?php
/***
 * JSON Web Signature (JWS) represents content secured with digital
 * signatures or Message Authentication Codes (MACs) using JavaScript
 * Object Notation (JSON) based data structures.  Cryptographic
 * algorithms and identifiers for use with this specification are
 * described in the separate JSON Web Algorithms (JWA) specification and
 * an IANA registry defined by that specification.  Related encryption
 * capabilities are described in the separate JSON Web Encryption (JWE)
 * specification.
 */

namespace yii\authclient\jose;

use yii\base\Exception;
use yii\base\Object;
use yii\helpers\Json;

class Jws extends Jose {

    public $payload;

    public function __construct(SignableInterface $signable) {
        $this->header = $signable->getHeader();
        $this->payload = $signable->getPayload();
    }


    public function sign()
    {

    }

    public function verify()
    {

    }


}
