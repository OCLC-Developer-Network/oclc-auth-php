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
use OCLC\Auth\RefreshToken;

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
        $this->wskey = $this->getMockBuilder(WSkey::class)
        	->setConstructorArgs($wskeyArgs)
        	->getMock();
        
        
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
    
    /**
     * can getContextInstitutionID
     */
    function testgetContextInstitutionID()
    {
    	$this->assertEquals('128807', $this->accessToken->getContextInstitutionID());
    }
    
    /**
     * can getAccessTokenUrl
     */
    function testgetAccessTokenUrl()
    {
    	$this->assertEquals('https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=client_credentials&authenticatingInstitutionId=128807&contextInstitutionId=128807&scope=WMS_NCIP WMS_ACQ', $this->accessToken->getAccessTokenUrl());
    }
    
    /**
     * @vcr accessTokenWithRefreshTokenSuccess
     * testProcessGoodAuthServerResponse
     */

    function testProcessGoodAuthServerResponse()
    {
        
        $this->accessToken->create($this->wskey);
        
        // Test all the properties are set from the JSON response
        $this->assertAttributeInternalType('array', 'response', $this->accessToken);
                
        $this->assertAttributeInternalType('string', 'accessTokenString', $this->accessToken);
        $this->assertAttributeEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', 'accessTokenString', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'expiresIn', $this->accessToken);
        $this->assertAttributeEquals('3599', 'expiresIn', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'expiresAt', $this->accessToken);
        $this->assertAttributeEquals('2018-08-23 18:45:29Z', 'expiresAt', $this->accessToken);
        
        $this->assertAttributeInternalType('string', 'contextInstitutionId', $this->accessToken);
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $this->accessToken);
        
        $this->assertInstanceOf('OCLC\Auth\RefreshToken', $this->accessToken->getRefreshToken());
        
        $this->assertInstanceOf('OCLC\User', $this->accessToken->getUser());
        
        $this->assertFalse($this->accessToken->isExpired());
        $this->assertEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', $this->accessToken->getValue());
        $this->assertEquals("2018-08-23 18:45:29Z", $this->accessToken->getExpiresAt());
        $this->assertEquals("3599", $this->accessToken->getExpiresIn());
        $this->assertEquals('bearer', $this->accessToken->getType());
        $this->assertNotNull($this->accessToken->getResponse());
        
    }
    
    /**
     * @vcr accessTokenRefreshSuccess
     * testRefresh
     */
    function testRefresh()
    {
    	$refreshToken = new refreshToken('rt_4393983rt_ZrigZXPJQnB1l2DxF1dCratGNxUHpGLjMw8z', '15000', '2080-08-23 18:45:29Z');
    	$options = array(
    			'accessTokenString' => 'tk_12345',
    			'expiresAt' => '2080-08-23 18:45:29Z',
    			'expiresIn' => '3599',
    			'authenticatingInstitutionId' => '128807',
    			'contextInstitutionId' => '128807',
    			'refreshToken' => $refreshToken,
    			'scope' => static::$services,
    			'wskey' => $this->wskey
    			
    	);
    	$accessToken = new AccessToken('client_credentials', $options);
    	$accessToken->refresh();
    	
    	// Test all the properties are set from the JSON response
    	$this->assertAttributeInternalType('array', 'response', $accessToken);
    	
    	$this->assertAttributeInternalType('string', 'accessTokenString', $accessToken);
    	$this->assertAttributeEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', 'accessTokenString', $accessToken);
    	
    	$this->assertAttributeInternalType('string', 'expiresIn', $accessToken);
    	$this->assertAttributeEquals('3599', 'expiresIn', $accessToken);
    	
    	$this->assertAttributeInternalType('string', 'expiresAt', $accessToken);
    	$this->assertAttributeEquals('2018-08-23 18:45:29Z', 'expiresAt', $accessToken);
    	
    	$this->assertAttributeInternalType('string', 'contextInstitutionId', $accessToken);
    	$this->assertAttributeEquals('128807', 'contextInstitutionId', $accessToken);
    	
    	$this->assertInstanceOf('OCLC\Auth\RefreshToken', $accessToken->getRefreshToken());
    	
    	$this->assertInstanceOf('OCLC\User', $accessToken->getUser());
    	
    	$this->assertFalse($accessToken->isExpired());
    	$this->assertEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', $accessToken->getValue());
    	$this->assertEquals("2018-08-23 18:45:29Z", $accessToken->getExpiresAt());
    	$this->assertEquals("3599", $accessToken->getExpiresIn());
    	$this->assertEquals('bearer', $accessToken->getType());
    	$this->assertNotNull($accessToken->getResponse());
    	
    }
    
    /**
     * @vcr accessTokenRefreshSuccess
     * testgetValueWithRefresh
     */
    function testgetValueWithRefresh()
    {
    	$refreshToken = new refreshToken('rt_4393983rt_ZrigZXPJQnB1l2DxF1dCratGNxUHpGLjMw8z', '15000', '2080-08-23 18:45:29Z');
    	$options = array(
    			'accessTokenString' => 'tk_12345',
    			'expiresAt' => '2013-08-23 18:45:29Z',
    			'expiresIn' => '3599',
    			'authenticatingInstitutionId' => '128807',
    			'contextInstitutionId' => '128807',
    			'refreshToken' => $refreshToken,
    			'scope' => static::$services,
    			'wskey' => $this->wskey
    			
    	);
    	$accessToken = new AccessToken('client_credentials', $options);
    	$this->assertEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', $accessToken->getValue());
    }
    
    /**
     * @vcr accessTokenWithRefreshTokenExpired
     * Test Getting an Access Token which is expired
     */
    
    function testProcessAccessTokenExpired()
    {
        $this->accessToken->create($this->wskey);
    
        // Test all the properties are set from the JSON response
        $this->assertAttributeInternalType('array', 'response', $this->accessToken);
    
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
        $this->assertNotNull($this->accessToken->getValue(false));
    }
    
    /**
     * @vcr accessTokenSuccess
     * testTestServerTrue
     */
    
    function testTestServerTrue(){
    	AccessToken::$testServer = true;
    	$this->accessToken->create($this->wskey);
    	
    	$this->assertTrue(AccessToken::$testServer);
    	
    }
    
    
    /**
     * @vcr accessTokenSuccess
     * testProcessGoodAuthServerResponseNoRefreshToken
     */
    
    function testProcessGoodAuthServerResponseNoRefreshToken()
    {
    
        $this->accessToken->create($this->wskey);
    
        // Test all the properties are set from the JSON response
        $this->assertAttributeInternalType('array', 'response', $this->accessToken);
    
        $this->assertAttributeInternalType('string', 'accessTokenString', $this->accessToken);
        $this->assertAttributeEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', 'accessTokenString', $this->accessToken);
    
        $this->assertAttributeInternalType('string', 'expiresIn', $this->accessToken);
        $this->assertAttributeEquals('3599', 'expiresIn', $this->accessToken);
    
        $this->assertAttributeInternalType('string', 'expiresAt', $this->accessToken);
        $this->assertAttributeEquals('2018-08-23 18:45:29Z', 'expiresAt', $this->accessToken);
    
        $this->assertAttributeInternalType('string', 'contextInstitutionId', $this->accessToken);
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $this->accessToken);
    
        $this->assertInstanceOf('OCLC\User', $this->accessToken->getUser());
    
        $this->assertFalse($this->accessToken->isExpired());
        $this->assertEquals('tk_Yebz4BpEp9dAsghA7KpWx6dYD1OZKWBlHjqW', $this->accessToken->getValue());
    }
    
    /**
     * Test creating an Access token when no scope present and debug on
     */
    
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
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage AccessToken must have an associated WSKey Property
     */
    function testMissingWSkey()
    {
    	$options = array(
    			'accessTokenString' => 'tk_12345',
    			'expiresAt' => '2018-08-23 18:45:29Z',
    			'expiresIn' => '3599',
    			'authenticatingInstitutionId' => '128807',
    			'contextInstitutionId' => '128807',
    			
    	);
    	$accessToken = new AccessToken('client_credentials', $options);
    	$accessToken->refresh();
    }
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage Sorry you do not have a valid Access Token
     */
    
    function testInvalidAccessToken()
    {
    	$options = array(
    			'accessTokenString' => 'tk_12345',
    			'expiresAt' => '2013-08-23 18:45:29Z',
    			'authenticatingInstitutionId' => '128807',
    			'contextInstitutionId' => '128807',
    			'scope' => static::$services,
    			'wskey' => $this->wskey
    			
    	);
    	$accessToken = new AccessToken('client_credentials', $options);
    	$this->assertTrue($accessToken->isExpired());
    	$accessToken->getValue();
    }

    /**
     * @vcr accessTokenFailure401
     * @expectedException Exception
     * @expectedExceptionMessage 401 WSKey test is invalid
     * testProcessBadAuthServerResponse401
     */
    function testProcessBadAuthServerResponse401()
    {
        $this->accessToken->create($this->wskey);
    }
    
    /**
     * @vcr accessTokenFailure403
     * @expectedException Exception
     * @expectedExceptionMessage 403 unauthorized_client
     * testProcessBadAuthServerResponse403
     */

    function testProcessBadAuthServerResponse403()
    {
        $this->accessToken->create($this->wskey);
    }
    
    /**
     * @vcr accessTokenFailure401_old
     * @expectedException Exception
     * @expectedExceptionMessage 401
     * testProcessBadAuthServerResponse401Old
     */
    function testProcessBadAuthServerResponse401Old()
    {
        $this->accessToken->create($this->wskey);
    }
    
    /**
     * @vcr accessTokenFailure401_html
     * @expectedException Exception
     * @expectedExceptionMessage 401
     * testProcessBadAuthServerResponse401Html
     */
    function testProcessBadAuthServerResponse401Html()
    {
    	$this->accessToken->create($this->wskey);
    }
    
    /**
     * @vcr accessTokenFailure403_old
     * @expectedException Exception
     * @expectedExceptionMessage 403 unauthorized_client
     * testProcessBadAuthServerResponse403Old
     */
    
    function testProcessBadAuthServerResponse403Old()
    {
        $this->accessToken->create($this->wskey);
    }
    
    /**
     * @vcr accessTokenFailure401xml
     * @expectedException Exception
     * @expectedExceptionMessage 401 Malformed JSON in response - Syntax error
     * testProcessBadAuthServerResponse401XML
     */
    
    function testProcessBadAuthServerResponse401XML()
    {
        $this->accessToken->create($this->wskey);
    }
}
