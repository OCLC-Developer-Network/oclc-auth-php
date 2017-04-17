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

use OCLC\Auth\AuthCode;

class AuthCodeTest extends \PHPUnit_Framework_TestCase
{

    private $authCode;

    private static $services = array(
        'WMS_NCIP',
        'WMS_ACQ'
    );

    private static $redirect_uri = 'http://library.worldshare.edu/test';

    function setUp()
    {
        $this->authCode = new authCode('test', static::$redirect_uri, static::$services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1));
    }

    /**
     * can create authCode
     */
    function testClientIDSet()
    {
        $this->assertAttributeInternalType('string', 'clientId', $this->authCode);
        $this->assertAttributeEquals('test', 'clientId', $this->authCode);
    }

    function testAuthenticatingInstitutionSet()
    {
        $this->assertAttributeInternalType('integer', 'authenticatingInstitutionId', $this->authCode);
        $this->assertAttributeEquals('1', 'authenticatingInstitutionId', $this->authCode);
    }

    function testContextInstitutionSet()
    {
        $this->assertAttributeInternalType('integer', 'contextInstitutionId', $this->authCode);
        $this->assertAttributeEquals('1', 'contextInstitutionId', $this->authCode);
    }

    function testRedirect_uriSet()
    {
        $this->assertAttributeInternalType('string', 'redirectUri', $this->authCode);
        $this->assertAttributeEquals(static::$redirect_uri, 'redirectUri', $this->authCode);
    }

    function testScopeSet()
    {
        $this->assertAttributeInternalType('array', 'scope', $this->authCode);
        $this->assertAttributeEquals(static::$services, 'scope', $this->authCode);
    }

    /**
     * can get Login URL
     */
    function testGetLoginURL()
    {
        $url = 'https://authn.sd00.worldcat.org/oauth2/authorizeCode?client_id=test&authenticatingInstitutionId=1&contextInstitutionId=1&redirect_uri=' . urlencode(static::$redirect_uri) . '&response_type=code&scope=WMS_NCIP WMS_ACQ';
        $this->assertEquals($this->authCode->getLoginURL(), $url);
    }
    
    /**
     * can get Login URL with no scope
     */
    function testNoScopeGetLoginURL()
    {
        $authCode = new authCode('test', static::$redirect_uri, null, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1, 'testMode' => true));
        $url = 'https://authn.sd00.worldcat.org/oauth2/authorizeCode?client_id=test&authenticatingInstitutionId=1&contextInstitutionId=1&redirect_uri=' . urlencode(static::$redirect_uri) . '&response_type=code';
        $this->assertEquals($authCode->getLoginURL(), $url);
    }
    
    /**
     * can get Login URL for WAYF screen
     */
    function testWAYFGetLoginURL()
    {
        $authCode = new authCode('test', static::$redirect_uri, static::$services);
        $url = 'https://authn.sd00.worldcat.org/oauth2/authorizeCode?client_id=test&redirect_uri=' . urlencode(static::$redirect_uri) . '&response_type=code&scope=WMS_NCIP WMS_ACQ';
        $this->assertEquals($authCode->getLoginURL(), $url);
    }
    
    
    /* Negative Test Cases */
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass a valid key to construct an AuthCode
     */
    function testEmptyClientID()
    {
        $this->authCode = new authCode('', static::$redirect_uri, static::$services);
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage If you pass a contextInstitutionId, you must pass an authenticatingInstitutionId
     */
    function testBadAuthenticatingInstitutionIdEmpty()
    {
        $this->authCode = new authCode('test', static::$redirect_uri, static::$services, array('contextInstitutionId' => 1));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid integer for the authenticatingInstitutionId
     */
    function testBadAuthenticatingInstitutionIdNotInteger()
    {
        $this->authCode = new authCode('test', static::$redirect_uri, static::$services, array('authenticatingInstitutionId' => 's', 'contextInstitutionId' => 1));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage If you pass an authenticatingInstitutionId, you must pass a contextInstitutionId
     */
    function testBadContextInstitutionIdEmpty()
    {
        $this->authCode = new authCode('test', static::$redirect_uri, static::$services, array('authenticatingInstitutionId' => 1));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid integer for the contextInstitutionId
     */
    function testBadContextInstitutionIdNotInteger()
    {
        $this->authCode = new authCode('test', static::$redirect_uri, static::$services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 's'));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid redirectUri
     */
    function testBadRedirectURI()
    {
        $this->authCode = new authCode('test', 'junk', static::$services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass an array of at least one scope
     */
    function testEmptyArrayScope()
    {
        $services = array();
        $this->authCode = new authCode('test', static::$redirect_uri, $services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1));
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass an array of at least one scope
     */
    function testNotArrayScope()
    {
        $services = ' ';
        $this->authCode = new authCode('test', static::$redirect_uri, $services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1));
    }
    
    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a redirectUri
     */
    function testNoRedirectURI()
    {
    	$this->authCode = new authCode('test', '', static::$services, array('authenticatingInstitutionId' => 1, 'contextInstitutionId' => 1));
    }
}
