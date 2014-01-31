<?php
Phar::mapPhar('oclc-auth.phar');

require_once 'phar://oclc-auth.phar/vendor/symfony/class-loader/Symfony/Component/ClassLoader/UniversalClassLoader.php';

$classLoader = new Symfony\Component\ClassLoader\UniversalClassLoader();
$classLoader->registerNamespaces(array(
    'OCLC' => 'phar://oclc-auth.phar/src',
    'Guzzle' => 'phar://oclc-auth.phar/vendor/guzzle/src',
    'Symfony\\Component\\EventDispatcher' => 'phar://oclc-auth.phar/vendor/symfony/event-dispatcher'
));
$classLoader->register();

__HALT_COMPILER();