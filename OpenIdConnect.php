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

    public $data;

    public $allowedAlgorithms = [
        'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
    ];

    public function init()
    {
        if ($this->data === null) {
            $this->data = array_merge($_GET, $_POST); // OPs may send data as POST or GET.
        }
    }

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
        if ($this->validateAuthState) {
            $authState = $this->getState('authState');
            if (!isset($_REQUEST['state']) || empty($authState) || strcmp($_REQUEST['state'], $authState) !== 0) {
                throw new HttpException(400, 'Invalid auth state parameter.');
            } else {
                $this->removeState('authState');
            }
        }

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
            ->setData(array_merge($defaultParams, $params))
            ->setHeaders($headers);

        $response = $this->sendRequest($request);

        $jwkSet = JWKFactory::createFromJKU($this->discover('jwks_uri'));
        $loader = new Loader();

        $idJws = $loader->loadAndVerifySignatureUsingKeySet(
            $response['id_token'],
            $jwkSet,
            $this->allowedAlgorithms
        );

        $accessJws = $loader->loadAndVerifySignatureUsingKeySet(
            $response['access_token'],
            $jwkSet,
            $this->allowedAlgorithms
        );

        $idToken = $idJws->getPayload();
        $accessToken = $accessJws->getPayload();

        if (!isset($idToken['iss']) || (strcmp($idToken['iss'], $this->getProviderURL()) !== 0)) {
            throw new HttpException(400, 'Invalid iss');
        }
        if (!isset($idToken['aud']) || (strcmp($idToken['aud'], $this->clientId) !== 0)) {
            throw new HttpException(400, 'Invalid aud');
        }
        if (!isset($accessToken['iss']) || (strcmp($accessToken['iss'], $this->getProviderURL()) !== 0)) {
            throw new HttpException(400, 'Invalid iss');
        }
        if (!isset($accessToken['aud']) || (strcmp($accessToken['aud'], $this->clientId) !== 0)) {
            throw new HttpException(400, 'Invalid aud');
        }

        if ($this->validateNonce) {
            $nonce = $this->getState('authNonce');
            if (!isset($idToken['nonce']) || empty($nonce) || strcmp($idToken['nonce'], $nonce) !== 0) {
                throw new HttpException(400, 'Invalid nonce.');
            } else {
                $this->removeState('authNonce');
            }
        }

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);
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