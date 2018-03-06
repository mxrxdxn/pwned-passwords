<?php

namespace PwnedPasswords;

class PwnedPasswords
{
    protected $apiURL = 'https://api.pwnedpasswords.com';

    public function getCount($password)
    {
        // We need to get the SHA1 of the password first before we send it to the Pwned Passwords API.
        $passwordHash = strtoupper(sha1($password));

        // We only need the first five characters.
        $passwordPrefix = substr($passwordHash, 0, 5);

        // Now we can fire it off to the API.
        $apiURL = $this->apiURL . '/range/' . $passwordPrefix;
        $ch = curl_init($apiURL);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $passwordList = curl_exec($ch);

        curl_close($ch);

        // We have our results - now let's loop them all.
        $passwordArray = explode(PHP_EOL, $passwordList);

        foreach ($passwordArray as $password) {
            // We need to extract the password hash.
            $passwordLine = explode(':', $password);

            $testHash = $passwordPrefix . trim(strtoupper($passwordLine[0]));

            // Check the password hash and see if it matches.
            if ($testHash === $passwordHash) {
                // The password has been found in $passwordArray - Return the amount
                return intval($passwordLine[1]);
            }
        }

        // Our password hasn't been included.
        return 0;
    }

    public function isInsecure($password, $maxUsage = 1)
    {
        // This is just a shorthand to remain backwards compatible. Calls the getCount function and compares the result with $maxUsage
        return (self::getCount($password) > $maxUsage);
    }
}
