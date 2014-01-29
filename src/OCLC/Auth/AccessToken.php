<?php
// Copyright 2013 OCLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
namespace OCLC\Auth;

use Guzzle\Http\Client;
use Guzzle\Plugin\History\HistoryPlugin;
use Guzzle\Plugin\Mock\MockPlugin;
use OCLC\Auth\WSKey;
use OCLC\User;

class AccessToken
{

    /**
     * A class that represents a client's OCLC Access Token.
     * An Access Token typically represents the rights of an application
     * - to access specific web services
     * - to interact with data at a specific insitution
     * - on behalf of a specific a given user
     * Access Tokens have several properties including
     * - Token String
     * - Token Type
     * - Expires
     * - Expires At
     * They also may have a Refresh Token Object with three properties
     * - Refresh Token (string value)
     * - Refresh Token Expires In
     * - Refresh Token Expires At
     *
     * @author Karen A. Coombs <coombsk@oclc.org>
     *        
     *         See the OCLC/Auth documentation for examples.
     *        
     * @var array static $authorization Server
     * @var array static $validOptions
     * @var array static $validGrantTypes
     * @var string $grant_type
     * @var integer $authenticatingInstitutionId;
     * @var integer $contextInstitutionId;
     * @var string $redirectUri;
     * @var array $scope
     * @var string $accessTokenUrl
     * @var array $headers
     * @var Guzzle\Http\Client\Request $lastRequest
     * @var OCLC\Auth\WSKey $wskey
     * @var OCLC\User $user
     * @var string $errorCode
     * @var string $errorWWWAuthenticate
     * @var string $errorMessage
     *     
     * @var string $response
     * @var string $type
     * @var string $accessTokenString
     * @var integer $expiresIn
     * @var string $expiresAt
     * @var OCLC\Auth\RefreshToken $refreshToken
     * @var string $mockResponseFilePath - file path to mock response
     *     
     */
    public static $authorizationServer = 'https://authn.sd00.worldcat.org/oauth2';

    public static $validOptions = array(
        'scope',
        'authenticatingInstitutionId',
        'contextInstitutionId',
        'redirectUri',
        'code',
        'refreshToken'
    );

    public static $validGrantTypes = array(
        'authorization_code',
        'refresh_token',
        'client_credentials'
    );

    private $authenticatingInstitutionId;

    private $contextInstitutionId;

    private $redirectUri;

    private $scope;
    
    private $headers;

    private $accessTokenUrl;

    public static $lastRequest = null;

    private $wskey = null;

    private $user = null;

    private $errorCode;

    private $errorWWWAuthenticate;

    private $errorMessage;

    private $response = null;

    private $type = null;

    private $accessTokenString = null;

    private $expiresIn = null;

    private $expiresAt = null;

    private $refreshToken = null;

    private $mockResponseFilePath = null;

    /**
     * Set Mock Response File path
     * sets the filename of a mock response so that testing can be performed
     *
     * @param
     *            $mockResponseFilePath
     *            
     */
    public function setMockResponseFilePath($mockResponseFilePath)
    {
        $this->mockResponseFilePath = $mockResponseFilePath;
    }

    /**
     * Get Error Code
     *
     * @return string
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }
    
    /**
     * Get Error Message
     *
     * @return string
     */
    public function getErrorMessage()
    {
        return $this->errorMessage;
    }

    /**
     * Get Context Institution ID
     *
     * @return integer
     */
    public function getContextInstitutionID()
    {
        return $this->contextInstitutionId;
    }

    /**
     * Get JSON Access Token Response
     *
     * @return string
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * Get Access Token Type
     *
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Get Value of Access Token
     *
     * @return string
     */
    public function getValue()
    {
        if (!empty($this->errorCode)) {
            throw new \LogicException($this->errorCode . ' ' . $this->errorMessage);
        }elseif (self::isExpired() && $this->refreshToken->isExpired()) {
            throw new \LogicException('Sorry you do not have a valid Access Token');
        } elseif (self::isExpired()) {
            self::refreshToken();
        }
        return $this->accessTokenString;
    }

    /**
     * Get Access Token Expires In
     *
     * @return integer
     */
    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    /**
     * Get Access Token Expires At
     *
     * @return string
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * Get User Object
     *
     * @return OCLC/User
     */
    public function getUser()
    {
        return $this->User;
    }

    /**
     * get Refresh Token
     *
     * @return OCLC/Auth/RefreshToken
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Return if the Access Token is Expired on Not
     *
     * @return boolean
     */
    public function isExpired()
    {
        date_default_timezone_set('UTC');
        if (strtotime($this->expiresAt) < time()) {
            $status = TRUE;
        } else {
            $status = FALSE;
        }
        return $status;
    }

    /**
     * Construct a new Access Token
     *
     * @param string $grant_type
     *            - there are three possible values: authorization_code, client_credentials, or refresh_token.
     *            Each of these require different options be set in the constructor
     *            - authorization_code
     *            -- code, redirect_uri, scope, authenticatingInstitutionId, contextInstitutionId must be set
     *            - client_credentials
     *            -- scope, authenticatingInstitutionId, contextInstitutionId must be set
     *            - refresh_token
     *            -- refresh_token option must be set
     * @param array $options
     *            - an associative array of options for constructing the Access Token. Possible indexes
     *            - $scope - array of scopes
     *            - $authenticatingInstitutionId
     *            - $contextInstitutionId
     *            - $redirect_uri
     *            - $code
     *            - $refresh_token
     */
    function __construct($grantType, $options)
    {
        if (empty($grantType) || ! in_array($grantType, static::$validGrantTypes)) {
            throw new \LogicException('You must pass a valid grant type to construct an Access Token');
        }
        $this->grantType = $grantType;
        
        if (empty($options) || ! is_array($options)) {
            throw new \BadMethodCallException('You must pass at least one option to construct an Access Token');
        }
        
        if ($this->grantType == 'authorization_code' && (empty($options['code']) || empty($options['authenticatingInstitutionId']) || empty($options['contextInstitutionId']))) {
            throw new \BadMethodCallException('You must pass the options: code, redirect_uri, scope, authenticatingInstitutionId, contextInstitutionId, to construct an Access Token using the authorization_code grant type');
        } elseif ($this->grantType == 'client_credentials' && (empty($options['authenticatingInstitutionId']) || empty($options['contextInstitutionId']) || empty($options['scope']))) {
            throw new \BadMethodCallException('You must pass the options: scope, authenticatingInstitutionId, contextInstitutionId, to construct an Access Token using the client_credential grant type');
        } elseif ($this->grantType == 'refresh_token' && empty($options['refreshToken'])) {
            throw new \BadMethodCallException('You must pass the option refreshToken to construct an Access Token using the refresh_token grant type');
        }
        
        foreach ($options as $name => $value) {
            if (in_array($name, static::$validOptions)) {
                $this->{$name} = $value;
            }
        }
        
        $this->accessTokenUrl = self::getAccessTokenURL();
    }

    /**
     * Create a new Access Token
     *
     * Create a new Access Token by making a request to the Authorization Server. If successful add properties to Access Token Object
     *
     * @param OCLC\Auth\WSKey $wskey
     *            A valid WSKey object
     * @param OCLC\User $user
     *            A valid User object
     * @throws Exception
     */
    public function create($wskey, $user = null)
    {
        // if you've got an unexpired refresh token use it
        if (! is_a($wskey, 'OCLC\Auth\WSKey')) {
            throw new \LogicException('You must pass a valid OCLC\Auth\WSKey object to create an Access Token');
        } elseif (isset($user) && ! is_a($user, 'OCLC\User')) {
            throw new \LogicException('You must pass a valid User object');
        }
        $this->wskey = $wskey;
        
        $options = array();
        if (isset($user)){
            $this->user = $user;
            $options['user'] = $this->user;
        }
        $authorization = $wskey->getHMACSignature('POST', $this->accessTokenUrl, $options);
        self::requestAccessToken($authorization, $this->accessTokenUrl);
    }

    public function refresh()
    {
        if (empty($this->wskey)) {
            throw new \LogicException('AccessToken must have an associated WSKey Property');
        }
        $this->grantType = 'refresh_token';
        $this->accessTokenUrl = self::getAccessTokenURL();
        $authorization = $this->wskey->getHMACSignature('POST', $this->accessTokenUrl);
        self::requestAccessToken($authorization, $this->accessTokenUrl);
    }

    private function requestAccessToken($authorization, $url)
    {
        $this->headers = array();
        $this->headers['Authorization'] = $authorization;
        $this->headers['Accept'] = 'application/json';
        
        $client = new Client();
        $client->setDefaultOption('timeout', 60);
        $client->setDefaultOption('redirect.strict', true);
        
        $history = new HistoryPlugin();
        $history->setLimit(1);
        $client->addSubscriber($history);
        if (defined('USER_AGENT')) {
            $userAgent = USER_AGENT;
        } else {
            $userAgent = 'OCLC Platform PHP Library';
        }
        $client->setUserAgent($userAgent);
        if (isset($this->mockResponseFilePath)) {
            $plugin = new MockPlugin();
            $client->addSubscriber($plugin);
            $plugin->addResponse($this->mockResponseFilePath);
        }
        $request = $client->createRequest('POST', $url, $this->headers);
        $request->getCurlOptions()->set(CURLOPT_SSL_VERIFYHOST, false);
        $request->getCurlOptions()->set(CURLOPT_SSL_VERIFYPEER, false);
        
        try {
            $response = $request->send();
            self::parseTokenResponse($response->json());
        } catch (\Guzzle\Http\Exception\BadResponseException $error) {
            $this->errorCode = (string) $error->getResponse()->getStatusCode();
            $this->errorWWWAuthenticate = $error->getResponse()->getWwwAuthenticate();
            $responseBody = json_decode($error->getResponse()->getBody(true), true);
            if (isset($responseBody['message'])) {
                $this->errorMessage = $responseBody['message'];
            } else {
                $this->errorMessage = $error->getResponse()->getBody(true);
            }
        }
        static::$lastRequest = $history->getLastRequest();
    }

    /**
     * Get the URL to retrieve the Access Token
     */
    private function getAccessTokenURL()
    {
        $access_token_url = static::$authorizationServer . '/accessToken?grant_type=' . $this->grantType;
        
        if ($this->grantType == 'refresh_token') {
            $access_token_url .= '&refresh_token=' . $this->refreshToken->getValue();
        } elseif ($this->grantType == 'authorization_code') {
            $access_token_url .= '&code=' . $this->code . '&authenticatingInstitutionId=' . $this->authenticatingInstitutionId . '&contextInstitutionId=' . $this->contextInstitutionId;
            $access_token_url .= '&redirect_uri=' . urlencode($this->redirectUri);
        } else {
            $access_token_url .= '&authenticatingInstitutionId=' . $this->authenticatingInstitutionId . '&contextInstitutionId=' . $this->contextInstitutionId . '&scope=' . implode($this->scope, ' ');
        }
        return $access_token_url;
    }

    /**
     * Parse the Access Token Response
     * Parses the Access Token Response received from the Authorization Server
     * and adds the relevant information to the Access Token object as properties
     *
     * @param string $responseJSON
     *            JSON Response from the Authorization Server
     */
    private function parseTokenResponse($responseJSON)
    {
        $this->response = $responseJSON;
        $this->accessTokenString = $this->response['access_token'];
        $this->expiresIn = $this->response['expires_in'];
        if (isset($this->response['expires_at'])) {
            $this->expiresAt = $this->response['expires_at'];
        }
        if (isset($this->response['contextInstitutionId'])) {
            $this->contextInstitutionId = $this->response['contextInstitutionId'];
        }
        $this->type = $this->response['token_type'];
        if (! empty($this->response['principalID']) && ! empty($this->response['principalIDNS'])) {
            $this->User = new User($this->authenticatingInstitutionId, $this->response['principalID'], $this->response['principalIDNS']);
        }
        
        // Create a Refresh Token object
        if (isset($this->response['refresh_token'])) {
            $this->refreshToken = new RefreshToken($this->response['refresh_token'], $this->response['refresh_token_expires_in'], $this->response['refresh_token_expires_at']);
        }
    }
}
