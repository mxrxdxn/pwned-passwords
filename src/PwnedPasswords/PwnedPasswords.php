<?php

namespace PwnedPasswords;

class PwnedPasswords
{
    protected $apiURL = 'https://api.pwnedpasswords.com';

    public function isInsecure($password, $maxUsage = 1)
    {
        // We need to get the SHA1 of the password first before we send it to the Pwned Passwords API.
        $passwordHash = strtoupper(sha1($password));

        // We only need the first five characters.
        $passwordPrefix = substr($passwordHash, 0, 5);

        // Now we can fire it off to the API.
        $apiURL = $this->apiURL . '/range/' . $passwordPrefix;
        $ch     = curl_init($apiURL);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $passwordList = curl_exec($ch);

        curl_close($ch);

        // We have our results - now let's loop them all.
        $passwordArray = explode(PHP_EOL, $passwordList);

        foreach ($passwordArray as $password) {
            // We need to extract the password hash.
            $passwordLine = explode(':', $password);

            $testHash = $passwordPrefix . trim(strtoupper($passwordLine[0]));

            if ($testHash === $passwordHash) {
                if (intval(trim($passwordLine[0])) > $maxUsage) {
                    return true;
                }
            }
        }

        return false;
    }
}