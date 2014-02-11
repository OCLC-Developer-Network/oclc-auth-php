OCLC PHP Auth Library
=============
This library is a php wrapper around the Web Service Authentication system used by OCLC web services. 

## Installation

###Install from Phar

Each release includes an "oclc-auth.phar" file that includes all of the files needed to run the Auth library and all of its dependencies:
- [Guzzle for HTTP requests] (http://http://docs.guzzlephp.org)
- Symfony Class Loader
- Symfony Event Handler

Simply download the phar and include it in your project.
```php
require_once('phar://PATH_TO_THE_PHAR/oclc-auth.phar');
```
You can import the various classes into your code

```php
use OCLC\Auth\WSKey;
use OCLC\User;
```

###Install from zip

Each release includes an "oclc-auth.zip" file that includes all of the files needed to run the Auth library and all its dependecies:
- [Guzzle for HTTP requests] (http://http://docs.guzzlephp.org)
- Symfony Class Loader
- Symfony Event Handler

Simply download it and include the autoloader in your project.
Example:

```php
require_once '/PATH_TO_LIBRARY/autoload.php';

```

You can import the various classes into your code

```php
use OCLC\Auth\WSKey;
use OCLC\User;
```

## Usage
- Obtain an HMAC Signature
- Obtain an Access Token
-- Via Explicit Authorization Code
- Obtain User Identifiers

[See Examples](https://github.com/OCLC-Developer-Network/oclc-auth-php/blob/master/docs/example.rst)

###WSKey Configuration For Explicit Authorization Code Flow
In order to be able to use the Explicit Authorization Code flow your WSKey will need to be configured with a redirect URI. The redirect URI is the url your application lives at.
For example if my applicaiton lives at http://library.share.worldcat.org/myApp.php this will be your redirect URI. The redirect URI can be sest to localhost addresses for testing purposes.
If you need a new WSKey with a redirect_uri, this can be requested via Service Config.
If you already have a WSKey that you want a redirect_uri added to send an email to devnet[at]oclc[dot]org specifying your WorldCat username, the WSKey you want changed and the value of your redirect URI.