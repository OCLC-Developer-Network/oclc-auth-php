OCLC PHP Auth Library
=============
This library is a php wrapper around the Web Service Authentication system used by OCLC web services. 

## Installation

###Install from Phar

Each release includes an "oclc-auth.phar" file that includes all of the files needed to run the Auth library and all of its dependencies. Simply download the phar and include it in your project.
```php
require_once('/PATH_TO_THE_PHAR/oclc-auth.phar');
```
You can import the various classes into your code

```php
use OCLC\Auth\WSKey;
use OCLC\User;
```

###Install from source

1) Install dependencies: [Guzzle PHP](http://guzzlephp.org/)

2) Download the files from the src directory in GitHub.

3) Load the classes in your project. This can be done via an require statement or via an autoloader. The library uses the PSR-0 standard for auto-loading.
If you use Composer for your project you can load the library by listing it in the autoload section of your Composer JSON File. Symfony's autoloader class will work.
```php
require_once '/PATH_TO_SYMFONY/Symfony/Component/ClassLoader/UniversalClassLoader.php';

$classLoader = new Symfony\Component\ClassLoader\UniversalClassLoader();
$classLoader->registerNamespaces(array(
    'OCLC' => '/PATH_TO_/src',
    'Guzzle' => '/PATH_TO_/guzzle/src',
    'Symfony\\Component\\EventDispatcher' => '/PATH_TO_SYMFONY/symfony/event-dispatcher'
));
$classLoader->register();
```



## Usage
- Authenticate via the HMAC Pattern
- Obtain an Access Token
-- Via Explicit Authorization Code
- Obtain User Identifiers

[See Examples](https://github.com/OCLC-Developer-Network/oclc-auth-php/blob/master/docs/example.rst)