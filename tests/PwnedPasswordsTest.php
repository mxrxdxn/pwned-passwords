<?php

use PwnedPasswords\PwnedPasswords;

class PwnedPasswordsTest extends PHPUnit\Framework\TestCase
{
    /** @test */
    public function a_password_can_be_validated()
    {
        // Init the PwnedPasswords class
        $pwnedPasswords = new PwnedPasswords();

        // Test that a common "known" password appears correctly in the Pwned Passwords API
        $this->assertTrue($pwnedPasswords->checkIfPasswordIsBreached("password"));

        // Test that a "random" password does not appear in the Pwned Passwords API
        // This password may be in the API (but very unlikely)
        $this->assertFalse($pwnedPasswords->checkIfPasswordIsBreached("!!!PaSsWoRd " . mt_rand(100000000, 999999999)));
    }
}
