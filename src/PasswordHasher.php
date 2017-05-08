<?php
declare(strict_types=1);

namespace Jp\Hashing;

class PasswordHasher
{
    /**
     * Create a password hash from the given password.
     *
     * @param string $password
     *
     * @return string
     */
    public function createPasswordHash(string $password) : string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Does the given password match the saved password hash?
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function validatePassword(string $password, string $hash) : bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Does the given password hash need to be rehashed?
     *
     * @param string $hash
     *
     * @return bool
     */
    public function doesPasswordNeedRehash(string $hash) : bool
    {
        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

    /**
     * Is the given password hash a valid password hash per this password API?
     *
     * @param string $hash
     *
     * @return bool
     */
    public function isValidPasswordHash(string $hash) : bool
    {
        return password_get_info($hash)['algo'] !== 0;
    }
}
