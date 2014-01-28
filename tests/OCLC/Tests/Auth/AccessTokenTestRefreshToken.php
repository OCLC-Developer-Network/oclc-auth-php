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
use Guzzle\Http\Client;
use Guzzle\Plugin\History\HistoryPlugin;
use Guzzle\Plugin\Mock\MockPlugin;

class AccessTokenTestRefreshToken extends \PHPUnit_Framework_TestCase
{

    private $accessToken;

    private $options;

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
        
        $this->options = array(
            'refresh_token' => 'rt_239308230'
        );
        $this->accessToken = new AccessToken('refresh_token', $this->options);
    }

    /**
     * can construct Access Token
     */
    function testGrantTypeSet()
    {
        $this->assertAttributeInternalType('string', 'grantType', $this->accessToken);
        $this->assertAttributeEquals('refresh_token', 'grantType', $this->accessToken);
    }

    function testAccess_token_urlSetRefreshToken()
    {
        $desiredURL = 'https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=refresh_token&refresh_token=rt_239308230';
        $this->assertAttributeInternalType('string', 'accessTokenUrl', $this->accessToken);
        $this->assertAttributeEquals($desiredURL, 'accessTokenUrl', $this->accessToken);
    }

    function testRefreshTokenSet()
    {
        $this->assertAttributeInternalType('string', 'refreshToken', $this->accessToken);
        $this->assertAttributeEquals('rt_239308230', 'refreshToken', $this->accessToken);
    }

    /**
     * can create Access Token
     */
    function testCreateWithRefreshToken()
    {
        $accessTokenArgs = array(
            'refresh_token',
            $this->options
        );
        $accessTokenMock = $this->getMock('OCLC\Auth\AccessToken', array(
            'create'
        ), $accessTokenArgs);
        $accessTokenMock->expects($this->once())
            ->method('create')
            ->with($this->isInstanceOf('OCLC\Auth\WSKey'))
            ->will($this->returnSelf());
        $this->assertSame($accessTokenMock, $accessTokenMock->create($this->wskey));
    }
    
    /* Negative Test Cases */
    
    /**
     * @expectedException LogicException
     * @expectedExceptionMessage You must pass the option refresh_token to construct an Access Token using the refresh_token grant type
     */
    function testInvalidOptionsRefreshTokenGrantType()
    {
        $options = array(
            'code' => 'auth_239308230'
        );
        $this->accessToken = new AccessToken('refresh_token', $options);
    }
}
