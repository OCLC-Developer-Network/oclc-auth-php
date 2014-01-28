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
namespace OCLC\Tests\Auth;

use OCLC\Auth\WSKey;
use OCLC\Auth\AccessToken;
use OCLC\User;
use OCLC\RefreshToken;

class AccessTokenTest extends \PHPUnit_Framework_TestCase
{

    private $accessToken;

    private $wskey;

    private static $services = array(
        'WMS_NCIP',
        'WMS_ACQ'
    );

    private static $redirect_uri = 'http://library.worldshare.edu/test';

    function setUp()
    {
        $wskeyOptions = array(
            'redirectUri' => static::$redirect_uri,
            'services' => static::$services
        );
        $wskeyArgs = array(
            'test',
            'secret',
            $wskeyOptions
        );
        $this->wskey = $this->getMock('OCLC\Auth\WSKey', null, $wskeyArgs);
        
        $options = array(
            'authenticatingInstitutionId' => 128807,
            'contextInstitutionId' => 128807,
            'scope' => static::$services
        );
        $this->accessToken = new AccessToken('client_credentials', $options);
    }

    /**
     * can construct Access Token
     */
    function testGrantTypeSet()
    {
        $this->assertAttributeInternalType('string', 'grantType', $this->accessToken);
        $this->assertAttributeEquals('client_credentials', 'grantType', $this->accessToken);
    }

    function testProcessGoodAuthServerResponse()
    {
        $mock = __DIR__ . '/mocks/oauth_200_response.txt';
        $this->accessToken->setMockResponseFilePath($mock);
        
        $response = json_decode('{
"access_token":"tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW",
"token_type":"bearer",
"expires_in":"3599",
"principalID":"cpe4c7f6-f5a4-41fa-35c9-9d59443f544p",
"principalIDNS":"urn:oclc:platform:128807"
"contextInstitutionId": "128807",
"expires_at": "2013-08-23 18:45:29Z"
"refresh_token": "rt_ZrigZXPJQnB1l2DxF1dCratGNxUHpGLjMw8z",
"refresh_token_expires_in": "604799",
"refresh_token_expires_at": "2013-08-30 18:25:29Z"
}', true);
        
        $this->accessToken->create($this->wskey);
        
        // Test all the properties are set from the JSON response
        $this->assertAttributeInternalType('array', 'response', $this->accessToken);
        // $this->assertAttributeEquals($response, 'response', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'accessTokenString', $this->accessToken);
        $this->assertAttributeEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', 'accessTokenString', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'expiresIn', $this->accessToken);
        $this->assertAttributeEquals('3599', 'expiresIn', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'expiresAt', $this->accessToken);
        $this->assertAttributeEquals('2013-08-23 18:45:29Z', 'expiresAt', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'contextInstitutionId', $this->accessToken);
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $this->accessToken);
        
        $this->assertInstanceOf('OCLC\Auth\RefreshToken', $this->accessToken->getRefreshToken());
        
        $this->assertInstanceOf('OCLC\User', $this->accessToken->getUser());
        
        $this->assertTrue($this->accessToken->isExpired());
    }
    
    /* Negative Test Cases */
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass a valid grant type to construct an Access Token
     */
    function testInvalidGrantType()
    {
        $options = array(
            'refreshToken' => 'rt_239308230'
        );
        $this->accessToken = new AccessToken(' ', $options);
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass at least one option to construct an Access Token
     */
    function testInvalidOptions()
    {
        $options = ' ';
        $this->accessToken = new AccessToken('refresh_token', $options);
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass at least one option to construct an Access Token
     */
    function testEmptyArrayOptions()
    {
        $options = array();
        $this->accessToken = new AccessToken('refresh_token', $options);
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass a valid OCLC\Auth\WSKey object to create an Access Token
     */
    function testInvalidWSKey()
    {
        $this->accessToken->create(' ');
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass a valid User object
     */
    function testInvalidUser()
    {
        $User = ' ';
        $this->accessToken->create($this->wskey, $User);
    }

    function testProcessBadAuthServerResponse401()
    {
        $mock = __DIR__ . '/mocks/oauth_401_response.txt';
        $this->accessToken->setMockResponseFilePath($mock);
        $this->accessToken->create($this->wskey);
        
        $this->assertAttributeInternalType('string', 'errorCode', $this->accessToken);
        $this->assertAttributeEquals('401', 'errorCode', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'errorWWWAuthenticate', $this->accessToken);
        $this->assertAttributeEquals('WSKeyV2 error="invalid_token" error_description="request has invalid signature (l0rCvxM4kj+07kpBtZg+jQl3UNzo0jKxMevbC+HmhUE=)"', 'errorWWWAuthenticate', $this->accessToken);
    }

    function testProcessBadAuthServerResponse403()
    {
        $mock = __DIR__ . '/mocks/oauth_403_response.txt';
        $this->accessToken->setMockResponseFilePath($mock);
        $this->accessToken->create($this->wskey);
        
        $this->assertAttributeInternalType('string', 'errorCode', $this->accessToken);
        $this->assertAttributeEquals('403', 'errorCode', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'errorMessage', $this->accessToken);
        $this->assertAttributeEquals('unauthorized_client', 'errorMessage', $this->accessToken);
    }
}
