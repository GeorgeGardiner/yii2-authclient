<?php

namespace yii\authclient;

use Yii;
use yii\base\Exception;
use yii\helpers\Json;
use yii\web\HttpException;
use yii\base\Security;
use Jose\Factory\JWKFactory;
use Jose\Loader;

class OpenIdConnect extends OAuth2
{
    public $version = "Connect";

    public $providerUrl;

    public $validateNonce = true;

    private $providerConfig = [];

    private $authParams = [];

    private $responseTypes = ['code'];

    private $scopes = ['openid'];

    public $allowedAlgorithms = [
        'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
    ];


    public function buildAuthUrl(array $params = [])
    {
        $this->authUrl = $this->discover("authorization_endpoint");

        $defaultParams = [
            'response_type' => implode(' ', $this->responseTypes),
            'redirect_uri' => $this->getReturnUrl(),
            'client_id' => $this->clientId,
            'scope' => implode(' ', $this->scopes)
        ];

        if ($this->validateAuthState) {
            $authState = $this->generateAuthState();
            $this->setState('authState', $authState);
            $defaultParams['state'] = $authState;
        }

        if ($this->validateNonce) {
            $nonce = $this->generateNonce();
            $this->setState('authNonce', $nonce);
            $defaultParams['nonce'] = $nonce;
        }

        return $this->composeUrl($this->authUrl, array_merge($defaultParams, $params));
    }

    public function fetchAccessToken($authCode, array $params = [])
    {
        $headers = [];

        $defaultParams = [
            'grant_type' => 'authorization_code',
            'code' => $authCode,
            'redirect_uri' => $this->getReturnUrl(),
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        if (in_array('client_secret_basic', $this->discover("token_endpoint_auth_methods_supported"))) {
            $headers = ['Authorization: Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)];
            unset($defaultParams['client_secret']);
        }

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->discover("token_endpoint"))
            ->setData($defaultParams)
            ->setHeaders($headers);

        $token = $this->sendRequest($request);

        // We load the key set from an URL
        $jwkSet = JWKFactory::createFromJKU($this->discover('jwks_uri'));

        // We create our loader.
        $loader = new Loader();

        // The signature is verified using our key set.
        $jws = $loader->loadAndVerifySignatureUsingKeySet(
            $token,
            $jwkSet,
            $this->allowedAlgorithms,
            $signature_index
        );

        return $token;
    }


    private function generateNonce()
    {
        $nonce = Yii::$app->security->generateRandomString();
        return $nonce;
    }

    private function discover($param) {
        if (!isset($this->providerConfig[$param])) {
            $request = $this->createRequest()
                ->setMethod('GET')
                ->setUrl(rtrim($this->getProviderURL(),"/") . "/.well-known/openid-configuration");

            $response = $this->sendRequest($request);
            if (isset($response[$param])) {
                $this->providerConfig[$param] = $response[$param];
            } else {
                throw new Exception("Could not discover ".$param." from .well-known/openid-configuration");
            }
        }
        return $this->providerConfig[$param];
    }

    public function getProviderURL() {
        if (!isset($this->providerUrl)) {
            throw new Exception("The provider URL has not been set");
        } else {
            return $this->providerUrl;
        }
    }

    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    public function addAuthParam($param) {
        $this->authParams = array_merge($this->authParams, (array)$param);
    }

    public function initUserAttributes()
    {
        return [];
    }
}