Example: Read bib from WorldCat Metadata API
============================================
::
   This example reads a bibliographic record from the WorldCat Metadata API using the WSKey class to generate an HMAC signature for the authorization header.

.. code:: php

   use OCLC\Auth\WSKey;
   use OCLC\User;
   use Guzzle\Http\Client;
   
   $key = 'api-key';
   $secret = 'api-key-secret';
   $wskey = new WSKey($key, $secret);
   
   $url = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN';
   
   $user = new User('128807', 'principalID', 'principalIDNS');
   $options = array('User'=> $user);
   
   $authorizationHeader = $wskey->getHMACSignature('GET', $url, $options);
    
   $client = new Client();
   $headers = array();
   $headers['Authorization'] = $authorizationHeader;
   $request = $client->createRequest('GET', $url, $headers);
   $response = $request->send();
   echo $response->getBody(TRUE);

Example: App protected by an OAuth 2 Explicit Authorization login
=================================================================
::
   This example shows how to login a user and return the Access Token associated with their login to the screen
   
.. code:: php

   use OCLC\Auth\WSKey;
   use OCLC\Auth\AccessToken;
   use OCLC\User;
    
   $key = 'api-key';
   $secret = 'api-key-secret';
   $services = array('WMS_NCIP', 'WMS_ACQ');
   if (isset($_SERVER['HTTPS'])):
      $redirect_uri = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   else:
      $redirect_uri = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   endif;
    
   session_start();
    
   $options = array('services' => $services, 'redirectURI' => $redirect_uri);
   $wskey = new WSKey($key, $secret, $options);
    
   if (empty($_SESSION['AccessToken']) && empty($_GET['code']) {
      header("Location: " . $wskey->getLoginURL(128807, 128807), 'true', '303');
   } elseif (isset($_GET['code']) {
      $accessToken = $wskey->getAccessTokenWithAuthCode($_GET['code'], 128807, 128807);
    
      $_SESSION['AccessToken'] = $accessToken->getValue();
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   } else {
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   }
   
Example: Read bib from WorldCat Metadata API protected by an OAuth 2 Explicit Authorization login
=================================================================================================
::
   This example reads a bibliographic record from the WorldCat Metadata API using the WSKey class to 
   # login the user and obtain user identifiers from the Authorization Server
   # generate an HMAC signature for the authorization header.
   
.. code:: php

   use OCLC\Auth\WSKey;
   use OCLC\Auth\AccessToken;
   use OCLC\User;
   use Guzzle\Http\Client;
   
   /* setup the key, secret variables. Build an array of the IDs of the services you want to access */ 
   $key = 'api-key';
   $secret = 'api-key-secret';
   $services = array('WorldCatMetadataAPI');
   
   /* Determine the redirect_uri of your application*/
   if (isset($_SERVER['HTTPS'])):
      $redirect_uri = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   else:
      $redirect_uri = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   endif;
    
   session_start();
   
   /* Construct a new WSkey object using the key, secret and an options array that contains the services you want to access and your redirect_uri */ 
   $options = array('services' => $services, 'redirectURI' => $redirect_uri);
   $wskey = new WSKey($key, $secret, $options);
   
   /* See if you have an Access Token or Authorization Code already */ 
   if (empty($_SESSION['AccessToken']) && empty($_GET['code']) {
      /* if you don't have an Access token or Authorization Code, redirect the user to the login URL */
      header("Location: " . $wskey->getLoginURL(128807, 128807), 'true', '303');
   } else {
      if (empty($_SESSION['AccessToken'])) {
         /* if you do have an Authorization Code but not an Access Token, use the Authorization code to get an Access Token */
         $accessToken = $wskey->getAccessTokenWithAuthCode($_GET['code'], 128807, 128807);
    
         $_SESSION['AccessToken'] = $accessToken;
      } else {
         $accessToken = $_SESSION['AccessToken'];
      }
   
      $url = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN';
      
      /* Build a user object based on the principalID and principalIDNS from the Access Token */   
      $user = new User('128807', $AccessToken->getPrincipalID(), $AccessToken->getPrincipalIDNS());
      
      /* Get an HMAC Signature from your WSKey object using the method, url and options array which contains the User object */
      $options = array('User'=> $user);
      
      $authorizationHeader = $wskey->getHMACSignature('GET', $url, $options);
       
      $client = new Client();
      $headers = array();
      $headers['Authorization'] = $authorizationHeader;
      $request = $client->createRequest('GET', $url, $headers);
      $response = $request->send();
      echo $response->getBody(TRUE);
   }