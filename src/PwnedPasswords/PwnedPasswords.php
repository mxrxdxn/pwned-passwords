<?php

namespace PwnedPasswords;

use PwnedPasswords\Exceptions\InvalidPasswordException;
use PwnedPasswords\Exceptions\InvalidStatusCodeException;

class PwnedPasswords
{
    protected $baseUrl = "https://api.pwnedpasswords.com";

    public function checkIfPasswordIsBreached(string $password)
    {
        if (! empty($password)) {
            throw new InvalidPasswordException("There was no password to check.");
        }

        $client = $this->getGuzzleClient();

        $hashedPassword = strtoupper(sha1($password));
        $chars          = substr($hashedPassword, 0, 5);

        $response = $client->get(sprintf('/range/%s', $chars));

        if ($response->getStatusCode() !== 200) {
            throw new InvalidStatusCodeException(sprintf("Invalid status code returned from API request (%s), expected 200.", $response->getStatusCode()));
        }

        foreach (explode(PHP_EOL, $response->getBody()->getContents()) as $line) {
            $result = explode(':', $line);
            $hash   = $chars . $result[0];
            $hits   = $result[1];

            if ($hash === $hashedPassword) {
                return true;
            }
        }

        return false;
    }

    protected function getGuzzleClient()
    {
        return new \GuzzleHttp\Client([
            'base_uri' => $this->baseUrl
        ]);
    }
}