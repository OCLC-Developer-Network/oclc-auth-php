<?php
namespace OCLC\Tests\Auth;

use OCLC\Auth\WSKey;
use OCLC\Auth\AuthCode;
use OCLC\Auth\AccessToken;
use OCLC\User;

class WSKeyTest extends \PHPUnit_Framework_TestCase
{

    private $wskey;

    private $user;

    private static $services = array(
        'WMS_NCIP',
        'WMS_ACQ'
    );

    private static $redirect_uri = 'http://library.worldshare.edu/test';

    function setUp()
    {
        $options = array(
            'redirectUri' => static::$redirect_uri,
            'services' => static::$services
        );
        $this->wskey = new WSKey('test', 'secret', $options);
        
        $this->user = new User('128807', 'principalID', 'principalIDNS');
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

    function testRedirect_uriSet()
    {
        $this->assertAttributeInternalType('string', 'redirectUri', $this->wskey);
        // test to make sure it is a valid URL
        $this->assertAttributeEquals(static::$redirect_uri, 'redirectUri', $this->wskey);
    }

    function testServicesSet()
    {
        $this->assertAttributeInternalType('array', 'services', $this->wskey);
        $this->assertAttributeEquals(static::$services, 'services', $this->wskey);
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
     * getRedirectURI should return a valid URL string
     */
    function testgetRedirect_uri()
    {
        $this->assertEquals(static::$redirect_uri, $this->wskey->getRedirectUri());
    }

    /**
     * getServices should return an array of services
     */
    function testgetServices()
    {
        $this->assertEquals(static::$services, $this->wskey->getServices());
    }

    /**
     * getLoginURL should return a valid URL string
     */
    function testGetLoginURL()
    {
        $url = 'https://authn.sd00.worldcat.org/oauth2/authorizeCode?client_id=test&authenticatingInstitutionId=1&contextInstitutionId=1&redirect_uri=' . urlencode(static::$redirect_uri) . '&response_type=code&scope=WMS_NCIP,WMS_ACQ';
        $authCodeArgs = array(
            $this->wskey->getKey(),
            1,
            1,
            $this->wskey->getRedirectUri(),
            $this->wskey->getServices()
        );
        $authCode = $this->getMock('OCLC\Auth\AuthCode', array(
            'getLoginURL'
        ), $authCodeArgs);
        $authCode->expects($this->any())
            ->method('getLoginURL')
            ->will($this->returnValue($url));
        $this->assertEquals($this->wskey->getLoginURL(1, 1), $url);
    }

    /**
     * getAccessTokenWithAuthCode should return a valid Access Token object
     */
    function testgetAccessTokenWithAuthCode()
    {
        $mock = __DIR__ . '/mocks/oauth_200_response.txt';
        $this->wskey->setMockResponseFilePath($mock);
        
        $desiredURL = 'https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=authorization_code&code=auth_12384794&authenticatingInstitutionId=128807&contextInstitutionId=128807&redirect_uri=' . urlencode(static::$redirect_uri);
        
        $AccessToken = $this->wskey->getAccessTokenWithAuthCode('auth_12384794', 128807, 128807);
        $this->assertInstanceOf('OCLC\Auth\AccessToken', $AccessToken);
        
        $this->assertAttributeInternalType('string', 'grantType', $AccessToken);
        $this->assertAttributeEquals('authorization_code', 'grantType', $AccessToken);
        
        $this->assertAttributeEquals('auth_12384794', 'code', $AccessToken);
        
        $this->assertAttributeEquals('128807', 'authenticatingInstitutionId', $AccessToken);
        
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $AccessToken);
        
        $this->assertAttributeEquals($desiredURL, 'accessTokenUrl', $AccessToken);
    }

    /**
     * getAccessTokenWithClientCredentials should return a valid Access Token object
     */
    function testgetAccessTokenWithClientCredentials()
    {
        $mock = __DIR__ . '/mocks/oauth_200_response.txt';
        $this->wskey->setMockResponseFilePath($mock);
        
        $AccessToken = $this->wskey->getAccessTokenWithClientCredentials(128807, 128807, $this->user);
        $this->assertInstanceOf('OCLC\Auth\AccessToken', $AccessToken);
        
        $this->assertAttributeInternalType('string', 'grantType', $AccessToken);
        $this->assertAttributeEquals('client_credentials', 'grantType', $AccessToken);
        
        $this->assertAttributeEquals('128807', 'authenticatingInstitutionId', $AccessToken);
        
        $this->assertAttributeEquals('128807', 'contextInstitutionId', $AccessToken);
        
        $this->assertInstanceOf('OCLC\User', $AccessToken->getUser());
    }

    /**
     * getHMACSignature should return a valid HMAC Signature
     */
    function testgetHMACSignatureNoUser()
    {
        $Signature = 'http://www.worldcat.org/wskey/v2/hmac/v1 clientId="test", timestamp="1386968102", nonce="2382dbb7", signature="y0avD+LN2+UwehWjnezKgtECVcpD6a9ff7HBldQfKUQ="';
        // hardcode nonce and timestamp
        
        $this->wskey->setDebugNonce('2382dbb7');
        $this->wskey->setDebugTimestamp(1386968102);
        
        $this->assertEquals($this->wskey->getHMACSignature('GET', 'http://www.oclc.org/test'), $Signature);
    }

    function testgetHMACSignatureUser()
    {
        $Signature = 'http://www.worldcat.org/wskey/v2/hmac/v1 clientId="test", timestamp="1386968102", nonce="2382dbb7", signature="y0avD+LN2+UwehWjnezKgtECVcpD6a9ff7HBldQfKUQ=", principalID="principalID", principalIDNS="principalIDNS"';
        $User = new User('128807', 'principalID', 'principalIDNS');
        
        // hardcode nonce and timestamp
        $this->wskey->setDebugNonce('2382dbb7');
        $this->wskey->setDebugTimestamp(1386968102);
        
        $options = array(
            'user' => $User
        );
        
        $this->assertEquals($this->wskey->getHMACSignature('GET', 'http://www.oclc.org/test', $options), $Signature);
    }

    function testgetHMACSignatureUser_ExtraAuthInfo()
    {
        $Signature = 'http://www.worldcat.org/wskey/v2/hmac/v1 clientId="test", timestamp="1386968102", nonce="2382dbb7", signature="y0avD+LN2+UwehWjnezKgtECVcpD6a9ff7HBldQfKUQ=", principalID="principalID", principalIDNS="principalIDNS", username="testuser"';
        $User = new User('128807', 'principalID', 'principalIDNS');
        
        // hardcode nonce and timestamp
        $this->wskey->setDebugNonce('2382dbb7');
        $this->wskey->setDebugTimestamp(1386968102);
        
        $options = array(
            'user' => $User,
            'authParams' => array(
                'username' => 'testuser'
            )
        );
        
        $this->assertEquals($this->wskey->getHMACSignature('GET', 'http://www.oclc.org/test', $options), $Signature);
    }
    
    /* Negative Test Cases */
    
    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid key and secret to construct a WSKey
     */
    function testEmptyWSKey()
    {
        $this->wskey = new WSKey('', 'secret');
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid array of options
     */
    function testEmptyOptionsArray()
    {
        $options = array();
        $this->wskey = new WSKey('test', 'secret', $options);
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid array of options
     */
    function testOptionsNotArray()
    {
        $options = 'la';
        $this->wskey = new WSKey('test', 'secret', $options);
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid key and secret to construct a WSKey
     */
    function testEmptySecret()
    {
        $this->wskey = new WSKey('test', '');
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass a valid redirectUri
     */
    function testBadRedirectURI()
    {
        $services = array(
            'WMS_NCIP',
            'WMS_ACQ'
        );
        $options = array(
            'redirectUri' => 'junk',
            'services' => $services
        );
        $this->wskey = new WSKey('test', 'secret', $options);
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass an array of at least one service
     */
    function testEmptyArrayServices()
    {
        $services = array();
        $options = array(
            'redirectUri' => 'http://www.oclc.org/test',
            'services' => $services
        );
        $this->wskey = new WSKey('test', 'secret', $options);
    }

    /**
     * @expectedException BadMethodCallException
     * @expectedExceptionMessage You must pass an array of at least one service
     */
    function testNotArrayServices()
    {
        $services = ' ';
        $options = array(
            'redirectUri' => 'http://www.oclc.org/test',
            'services' => $services
        );
        $this->wskey = new WSKey('test', 'secret', $options);
    }
}
