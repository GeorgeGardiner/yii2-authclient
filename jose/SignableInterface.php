<?php

namespace yii\authclient\jose;

interface SignableInterface
{
    public function getHeader();

    public function getPayload();

}
