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
use Zend\Log\Writer\Mock;
use Zend\Log\Logger;
use Zend\Log\PsrLoggerAdapter;

class AccessTokenLoggerTest extends \PHPUnit_Framework_TestCase
{

    private $accessToken;

    private $options;

    private $wskey;

    private static $services = array(
        'WMS_NCIP',
        'WMS_ACQ',
        'refresh_token'
    );

    function setUp()
    {
        $this->logMock = new Mock();
        $logger = new Logger();
        $logger->addWriter($this->logMock);
        $psrLogger = new PsrLoggerAdapter($logger);
        
        $wskeyOptions = array(
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
        
        $this->options = array(
            'authenticatingInstitutionId' => 128807,
            'contextInstitutionId' => 128807,
            'scope' => static::$services,
            'logger' => $psrLogger
        );
        $this->accessToken = new AccessToken('client_credentials', $this->options);
        
    }
    
    /**
     * can construct Access Token
     */
    function testGrantTypeSet()
    {
        $this->assertAttributeInternalType('string', 'grantType', $this->accessToken);
        $this->assertAttributeEquals('client_credentials', 'grantType', $this->accessToken);
    }
    
    function testAuthenticatingInstitutionSet()
    {
        $this->assertAttributeInternalType('integer', 'authenticatingInstitutionId', $this->accessToken);
        $this->assertAttributeEquals('128807', 'authenticatingInstitutionId', $this->accessToken);
    }
    
    function testContextInstitutionSet()
    {
        $this->assertAttributeInternalType('integer', 'contextInstitutionId', $this->accessToken);
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $this->accessToken);
    }
    
    function testScopeSet()
    {
        $this->assertAttributeInternalType('array', 'scope', $this->accessToken);
        $this->assertAttributeEquals(static::$services, 'scope', $this->accessToken);
    }
    
    function testAccess_token_urlSet()
    {
        $desiredURL = 'https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=client_credentials&authenticatingInstitutionId=128807&contextInstitutionId=128807&scope=' . implode(static::$services, ' ');
    
        $this->assertAttributeInternalType('string', 'accessTokenUrl', $this->accessToken);
        $this->assertAttributeEquals($desiredURL, 'accessTokenUrl', $this->accessToken);
    }
    
    function testAccess_token_LoggerSet()
    {
        $this->assertAttributeInstanceOf('Psr\Log\LoggerInterface', 'logger', $this->accessToken);
    }

    /**
     * @vcr accessTokenWithRefreshTokenSuccess
     * can log getting an Access Token
     */

    function testLogger()
    {
        $this->accessToken->create($this->wskey);
        $this->assertNotEmpty($this->logMock);
    }
    
    /**
     * @vcr accessTokenWithRefreshTokenSuccess
     * can log getting an Access Token
     */
    
    function testLoggerSpecifyFormat()
    {
    	$logMock = new Mock();
    	$logger = new Logger();
    	$logger->addWriter($logMock);
    	$psrLogger = new PsrLoggerAdapter($logger);
    	
    	$wskeyOptions = array(
    			'services' => static::$services
    	);
    	$wskeyArgs = array(
    			'test',
    			'secret',
    			$wskeyOptions
    	);
    	
    	$wskey = $this->getMockBuilder(WSkey::class)
    	->setConstructorArgs($wskeyArgs)
    	->getMock();
    	
    	$options = array(
    			'authenticatingInstitutionId' => 128807,
    			'contextInstitutionId' => 128807,
    			'scope' => static::$services,
    			'logger' => $psrLogger,
    			'logFormat' => 'Request - {method} - {uri} - {code}'
    	);
    	$accessToken = new AccessToken('client_credentials', $options);
    	$accessToken->create($wskey);
    	$this->assertAttributeInternalType('string','logFormat', $accessToken);
    	$this->assertNotEmpty($logMock);
    	$this->assertContains('Request - POST - https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=client_credentials&authenticatingInstitutionId=128807&contextInstitutionId=128807&scope=WMS_NCIP%20WMS_ACQ%20refresh_token - 200', $logMock->events[0]['message']);
    }
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The logger must be an object that uses a valid Psr\Log\LoggerInterface interface
     */
    function testNotValidLoggerInterface()
    {
        $options = array(
            'authenticatingInstitutionId' => 128807,
            'contextInstitutionId' => 128807,
            'scope' => static::$services,
            'logger' => 'lala'
        );
        $this->accessToken = new AccessToken('client_credentials', $options);
    }
}
