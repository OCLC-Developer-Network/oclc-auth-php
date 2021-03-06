Introduction
============

All of these examples assume the library has been installed via Composer and have the require statement based on that. 
The require statements for the alternative installation methods are all present but commented out

Example: Read bib from WorldCat Metadata API
============================================

This example reads a bibliographic record from the WorldCat Metadata API using the WSKey class to generate an HMAC signature for the authorization header.

.. code:: php

   require_once('vendor/autoload.php');
   
   /*
   // installed via Phar
   require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
   
   // installed via Zip
   require_once '/PATH_TO_LIBRARY/autoload.php';
   */

   use OCLC\Auth\WSKey;
   use OCLC\User;
   use GuzzleHttp\Client;
   use GuzzleHttp\Exception\RequestException;
   
   $key = 'api-key';
   $secret = 'api-key-secret';
   $wskey = new WSKey($key, $secret);
   
   $url = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN';
   
   $user = new User('128807', 'principalID', 'principalIDNS');
   $options = array('user'=> $user);
   
   $authorizationHeader = $wskey->getHMACSignature('GET', $url, $options);
    
   $client = new Client(
       [
        'curl' => [
            CURLOPT_SSLVERSION => '3'
       ]]
   );
   $headers = array();
   $headers['Authorization'] = $authorizationHeader;
   
   try {
        $response = $client->request('GET', $url, ['headers' => $headers]);
        echo $response->getBody(TRUE);
   } catch (RequestException $error) {
        echo $error->getResponse()->getStatusCode();
        echo $error->getResponse()->getBody(true);
   }
  
Example: Get Access Token with Client Credential Grant
======================================================
This example shows how to retrieve an Access Token using the Client Credential Grant pattern . It assumes that the Sandbox Institution is being interacted with

.. code:: php

   require_once('vendor/autoload.php');
   
   /*
   // installed via Phar
   require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
   
   // installed via Zip
   require_once '/PATH_TO_LIBRARY/autoload.php';
   */

   use OCLC\Auth\WSKey;
   use OCLC\Auth\AccessToken;
   use OCLC\User;
    
   $key = 'api-key';
   $secret = 'api-key-secret';
   $services = array('WMS_NCIP', 'WMS_ACQ');
    
   $user = new User('128807', 'principalID', 'principalIDNS'); 
   $options = array('services' => $services);
   $wskey = new WSKey($key, $secret, $options);
    
   $accessToken = $wskey->getAccessTokenWithClientCredentials(128807, 128807, $user);
 
   echo 'Hello you have an Access Token - ' . $accessToken->getValue();

Example: App protected by an OAuth 2 Explicit Authorization login
=================================================================
This example shows how to login a user and return the Access Token associated with their login to the screen. It assumes that the Sandbox Institution is being interacted with
   
.. code:: php

   require_once('vendor/autoload.php');
   
   /*
   // installed via Phar
   require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
   
   // installed via Zip
   require_once '/PATH_TO_LIBRARY/autoload.php';
   */

   use OCLC\Auth\WSKey;
   use OCLC\Auth\AccessToken;
   use OCLC\User;
    
   $key = 'api-key';
   $secret = 'api-key-secret';
   $services = array('WMS_NCIP', 'WMS_ACQ', 'refresh_token');
   if (isset($_SERVER['HTTPS'])):
      $redirect_uri = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   else:
      $redirect_uri = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   endif;
    
   session_start();
    
   $options = array('services' => $services, 'redirectUri' => $redirect_uri);
   $wskey = new WSKey($key, $secret, $options);
    
   if (empty($_SESSION['AccessToken']) && empty($_GET['code'])) {
      header("Location: " . $wskey->getLoginURL(128807, 128807), 'true', '303');
   } elseif (isset($_GET['code'])) {
      // returns an Access Token object with a refresh token object embedded.
      $accessToken = $wskey->getAccessTokenWithAuthCode($_GET['code'], 128807, 128807);
    
      $_SESSION['AccessToken'] = $accessToken->getValue();
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   } else {
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   }
   
Example: App protected by an OAuth 2 Explicit Authorization login using WAYF
============================================================================
This example shows how to login a user and return the Access Token associated with their login to the screen. It assumes that the user's institution is unknown at the user needs to use a WAYF screen
   
.. code:: php

   require_once('vendor/autoload.php');
   
   /*
   // installed via Phar
   require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
   
   // installed via Zip
   require_once '/PATH_TO_LIBRARY/autoload.php';
   */

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
    
   $options = array('services' => $services, 'redirectUri' => $redirect_uri);
   $wskey = new WSKey($key, $secret, $options);
    
   if (empty($_SESSION['AccessToken']) && empty($_GET['code']) && empty($_GET['authenticatingInstitutionId'] && empty($_GET['contextInstitutionId'])) {
      header("Location: " . $wskey->getLoginURL(), 'true', '303');
   } elseif (isset($_GET['code']) && isset($_GET['authenticatingInstitutionId']) && isset($_GET['contextInstitutionId'])) {
      $accessToken = $wskey->getAccessTokenWithAuthCode($_GET['code'], $_GET['authenticatingInstitutionId'], $_GET['contextInstitutionId']);
    
      $_SESSION['AccessToken'] = $accessToken->getValue();
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   } else {
      echo 'Hello you have an Access Token - ' . $_SESSION['AccessToken'];
   }   
   
Example: Read bib from WorldCat Metadata API protected by an OAuth 2 Explicit Authorization login
=================================================================================================
This example reads a bibliographic record from the WorldCat Metadata API using the WSKey class to 
- login the user and obtain user identifiers from the Authorization Server
- generate an HMAC signature for the authorization header.
   
.. code:: php

   require_once('vendor/autoload.php');
   
   /*
   // installed via Phar
   require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
   
   // installed via Zip
   require_once '/PATH_TO_LIBRARY/autoload.php';
   */

   use OCLC\Auth\WSKey;
   use OCLC\User;
   use GuzzleHttp\Client;
   use GuzzleHttp\Exception\RequestException;
   
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
   $options = array('services' => $services, 'redirectUri' => $redirect_uri);
   $wskey = new WSKey($key, $secret, $options);
   
   /* See if you have an Access Token or Authorization Code already */ 
   if (empty($_SESSION['AccessToken']) && empty($_GET['code'])) {
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
      
      /* Retrieve a user object from the Access Token */   
      $user = $accessToken->getUser();
       
      $client = new Client(
         [
         'curl' => [
               CURLOPT_SSLVERSION => '3'
          ]]
      );
      $headers = array();
      $headers['Authorization'] = 'Bearer ' . $accessToken->getValue();
      try {
         $response = $client->request('GET', $url, ['headers' => $headers]);
         echo $response->getBody(TRUE);
      } catch (RequestException $error) {
         echo $error->getResponse()->getStatusCode();
         echo $error->getResponse()->getBody(true);
      }
   }
