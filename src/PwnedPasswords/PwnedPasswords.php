<?php

namespace PwnedPasswords;

class PwnedPasswords
{
    const API = 'https://api.pwnedpasswords.com/range/';

    private $cache;
    
    public function __construct() 
    {
        $this->cache = [];   
    }
    
    public function getCount(string $password): int
    {
        // We need to get the SHA1 of the password first before we send it to the Pwned Passwords API.
        $password = strtoupper(sha1($password));

        // check if the password have been already check 
        if(isset($this->cache[$password])) {
            // return result from cache
            return $this->cache[$password]);   
        }
        
        $this->cache[$password] = 0;
        
        // We only need the first five characters.
        $prefix = substr($password, 0, 5);

        // Now we can fire it off to the API.
        $url = static::API . $prefix;

        $ch = curl_init();
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt( $ch, CURLOPT_URL, $url );
        curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, FALSE );
        curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0 );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, TRUE );
        curl_setopt( $ch, CURLOPT_HTTPHEADER, [ 'method' => 'GET' ] );
        curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
        $response = curl_exec($ch);
        curl_close($ch);

        // We have our results - now let's loop them all.
        $result = explode(PHP_EOL, $response);

        foreach ($result as $line) {
            // We need to extract the password hash.
            list($hash,$count) = explode(':', $line);
            // Check the password hash and see if it matches.
            if (trim(strtoupper($prefix . $hash)) === $password) {
                // The password has been found in the result - Return the count
                $this->cache[$password] = (int) $count;
            }
        }

        // Our password hasn't been included.
        return $this->cache[$password];
    }

    /**
     * This is just a shorthand to remain backwards compatible.
     * Calls the getCount function and compares the result with $maxUsage
     * @deprecated
     * @param string $password
     * @param int $maxUsage
     * @return bool
     */
    public function isInsecure(string $password,int $maxUsage = 0): bool
    {
        $count = $this->getCount($password);
        return $count > $maxUsage;
    }
}
