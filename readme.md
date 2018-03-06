
# PwnedPasswords
A library to query Troy Hunt's Pwned Passwords service to see whether or not a password has been included in a public breach.

# Requirements

 - PHP >= 5.0.0
 - ext-curl

# Installation
Installing PwnedPasswords is made easy via Composer. Just require the package using the command below, and you are ready to go.

    composer require ron-maxweb/pwned-passwords
    
# Usage
To use the library, you can do something along the lines of the following.
```php
<?php

require_once('vendor/autoload.php');

$pp = new PwnedPasswords\PwnedPasswords;

var_dump($pp->isInsecure('password'));
```
The `isInsecure` method will return true if the password has been found in the PwnedPasswords API, and false if not.

You can also check if passwords have been used more than *x* times by supplying a second argument to the `isInsecure` method as below.
```php
<?php

require_once('vendor/autoload.php');

$pp = new PwnedPasswords\PwnedPasswords;

var_dump($pp->isInsecure('password', 5));
```
The method will now return true if it has been found in the PwnedPasswords API more than 5 times.


If you want to build your own thresholds (Ex. display a warning if the password has been found more than once and an error if more than 5x) you can call the `isInsecure` method like below.
```php
<?php

require_once('vendor/autoload.php');

$pp = new PwnedPasswords\PwnedPasswords;

$count = $pp->getCount('password');

var_dump($count);
```
The method will return the amount the password has been found in the PwnedPasswords API.


# Issues
Please feel free to use the Github issue tracker to post any issues you have with this library.
