<?php
declare(strict_types=1);

namespace Jp\Hashing;

use Exception;

final class TokenHasher
{
    /**
     * Generate a random string of given length.
     *
     * @param int $length
     *
     * @throws Exception if $length is invalid.
     *
     * @return string
     */
    public function generateRandomToken(int $length = 32) : string
    {
        if ($length <= 0) {
            throw new Exception('Invalid token length given: ' . $length);
        }

        $byteLength = $length % 2 === 0
            ? $length
            : $length + 1
        ;

        $bytes = random_bytes($byteLength);

        $hex = bin2hex($bytes);

        return mb_substr($hex, 0, $length);
    }

    /**
     * Create a secure hash from the given token.
     *
     * @param string $token
     *
     * @return string
     */
    public function createTokenHash(string $token) : string
    {
        return hash('sha256', $token);
    }

    /**
     * Does the token match the hash?
     *
     * @param string $token
     * @param string $hash
     *
     * @return bool
     */
    public function validateToken(string $token, string $hash) : bool
    {
        return hash_equals($hash, hash('sha256', $token));
    }
}
