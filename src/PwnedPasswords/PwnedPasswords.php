<?php

namespace PwnedPasswords;

use RuntimeException;

use RuntimeException;
use InvaliArgumentException;

class PwnedPasswords
{
    const API = 'https://api.pwnedpasswords.com/range/';
	
    const CURL = 2;
    
    const FILE = 4;
    
    /**
    * cached result 
    * @var array $cache
    */
    private $cache;
    
    /**
    * 
    * @var array $options 
    */
    private $options;
    
    public function __construct(int $method = null,array $curlOptions = []) 
    {
        $this->cache = [];   
        $this->options = [
            'method' => $method, 
            'curl' => $curlOptions
        ];
    }
    
    private function fetch(string $url): string
    {
		if($this->options['method'] === null) {
			try {
				return $this->fetchCurl($url);
			} catch (RuntimeException $e) {
				return $this->fetchFile($url);
			}
		} elseif($this->options['method'] === static::CURL) {   
			return $this->fetchCurl($url);
		} elseif ($this->options['method'] === static::FILE) {
            return $this->fetchFile($url);
        } else {
            throw new InvaliArgumentException("Unsupported method {$this->options['method']}");   
        }
    }
    
    private function fetchFile(string $file): string
    {
        return file_get_contents($file);   
    }
    
    private function fetchCurl(string $url): string 
    {
        $ch = curl_init();
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt( $ch, CURLOPT_URL, $url );
        curl_setopt( $ch, CURLOPT_HTTPHEADER, [ 'method' => 'GET' ] );
        curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
        foreach($this->options['curl'] as $option => $value) {
            curl_setopt( $ch, $option, $value);   
        }
        $response = curl_exec($ch);
        if(curl_errno($ch) !== 0) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException($error);
        }
        curl_close($ch);
        return $response;
    }
    
    public function getCount(string $password): int
    {
        // We need to get the SHA1 of the password first before we send it to the Pwned Passwords API.
        $password = strtoupper(sha1($password));

        // check if the password have been already check 
        if(isset($this->cache[$password])) {
            // return result from cache
            return $this->cache[$password];   
        }
        
        $this->cache[$password] = 0;
        
        // We only need the first five characters.
        $prefix = substr($password, 0, 5);

        // Now we can fire it off to the API.
        $url = static::API . $prefix;

        $result = explode(PHP_EOL, $this->fetch($url));

        // We have our results - now let's loop them all.
        foreach ($result as $line) {
            // We need to extract the password hash.
            list($hash,$count) = explode(':', $line);
            // Check the password hash and see if it matches.
            if (trim(strtoupper($prefix . $hash)) === $password) {
                // The password has been found in the result 
                $this->cache[$password] = (int) $count;
            }
        }

        return $this->cache[$password];
    }

    /**
     * @param string $password
     * @return bool
     */
    public function isInsecure(string $password): bool
    {
		if( $password === '') {
			throw new InvaliArgumentException('password cannot be empty.');
		}
        return $this->getCount($password) > 0 ;
    }
}
