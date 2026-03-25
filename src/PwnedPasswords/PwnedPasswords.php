<?php

namespace PwnedPasswords;

use GuzzleHttp\Client;
use PwnedPasswords\Exceptions\InvalidPasswordException;
use PwnedPasswords\Exceptions\InvalidResponseException;

class PwnedPasswords
{
    protected $baseUrl = "https://api.pwnedpasswords.com";

    /**
     * @param string     $password
     * @param false|bool $getHits
     *
     * @return bool|int
     * @throws InvalidPasswordException
     * @throws InvalidResponseException
     */
    public function isPwned($password, $getHits = false)
    {
        if (empty($password)) {
            throw new InvalidPasswordException("There was no password to check.");
        }

        $client = $this->getGuzzleClient();

        $hashedPassword = strtoupper(sha1($password));
        $chars          = substr($hashedPassword, 0, 5);

        $response = $client->get(sprintf('/range/%s', $chars));

        if ($response->getStatusCode() !== 200) {
            throw new InvalidResponseException(sprintf("Invalid status code returned from API request (%s), expected 200.", $response->getStatusCode()));
        }

        foreach (explode("\r\n", $response->getBody()->getContents()) as $line) {
            $result = explode(':', $line);
            $hash   = $chars . $result[0];
            $hits   = intval($result[1]);

            if ($hash === $hashedPassword) {
                if ($getHits === true) {
                    return $hits;
                }

                return true;
            }
        }

        if ($getHits === true) {
            return 0;
        }

        return false;
    }

    /**
     * Return Guzzle client.
     *
     * @return Client
     */
    protected function getGuzzleClient()
    {
        return new Client([
            'base_uri' => $this->baseUrl
        ]);
    }
}