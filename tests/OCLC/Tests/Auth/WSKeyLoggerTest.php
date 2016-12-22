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

class WSKeyLoggerTest extends \PHPUnit_Framework_TestCase
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
        
        $this->options = array(
            'services' => static::$services,
            'logger' => $psrLogger
        );
        
        $this->wskey = new WSKey('test', 'secret', $this->options);
        
    }
    
    /**
     * can create WSKey
     */
    function testWSKeySet()
    {
        $this->assertAttributeInternalType('string', 'key', $this->wskey);
        $this->assertAttributeEquals('test', 'key', $this->wskey);
    }
    
    function testSecretSet()
    {
        $this->assertAttributeInternalType('string', 'secret', $this->wskey);
        $this->assertAttributeEquals('secret', 'secret', $this->wskey);
    }
    
    function testServicesSet()
    {
        $this->assertAttributeInternalType('array', 'services', $this->wskey);
        $this->assertAttributeEquals(static::$services, 'services', $this->wskey);
    }
    
    function testLoggerSet()
    {
        $this->assertAttributeInstanceOf('Psr\Log\LoggerInterface', 'logger', $this->wskey);
    }
    
    /**
     * getWSKey should return a WSKey String
     */
    function testgetWSKey()
    {
        $this->assertEquals('test', $this->wskey->getKey());
    }
    
    /**
     * getSecret should return a secret String
     */
    function testgetSecret()
    {
        $this->assertEquals('secret', $this->wskey->getSecret());
    }
    
    /**
     * getServices should return an array of services
     */
    function testgetServices()
    {
        $this->assertEquals(static::$services, $this->wskey->getServices());
    }

    /**
     * @vcr accessTokenWithRefreshTokenSuccess
     * can log getting an Access Token
     */

    function testLogger()
    {
        $user = new User(128807, 'principalID','principalIDNS');
        $accessToken = $this->wskey->getAccessTokenWithClientCredentials(128807, 128807, $user);
        $this->assertNotEmpty($this->logMock);
    }
    
    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage The logger must be an object that uses a valid Psr\Log\LoggerInterface interface
     */
    function testNotValidLoggerInterface()
    {
        $options = array(
            'services' => static::$services,
            'logger' => 'lala'
        );
        $this->wskey = new WSKey('test', 'secret', $options);
    }
}
