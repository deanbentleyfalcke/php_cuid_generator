<?php

namespace Cuid;

class Cuid {

    public static function generateCuid(int $length = 16, string $prefix = null): string {
        if ($length < 8 || $length > 32) {
            throw new \OutOfRangeException("Length must be between 8 and 32");
        }

        $hash = hash_init('xxh128');
        $prefix = $prefix ?? chr(random_int(97, 122));

        //Uniqeness by request
        $time = (string)(microtime(true)*1000);
        $counterValue = (int)(random_int(PHP_INT_MIN, PHP_INT_MAX) * 476782367);
        $random = bin2hex(random_bytes($length));

        //Fingerprint based on machine
        $host = self::getHostString();
        $process = (string)(getmypid() ?: random_int(1, 32768));

        //Build the hash
        hash_update($hash, $time);
        hash_update($hash, $counterValue);
        hash_update($hash, $random);
        hash_update($hash, $host);
        hash_update($hash, $process);

        $hash = hash_final($hash);

        if (extension_loaded('gmp')) {
            $result = gmp_strval(gmp_init($hash, 16), 36);
        } else {
            $result = base_convert($hash, 16, 36);
        }

        return $prefix . substr($result, 0, $length - 1);
    }

    private static function getHostString(): string
    {
        $fields = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_COMING_FROM',
            'HTTP_FORWARDED_FOR',
            'HTTP_CLIENT_IP',
            'HTTP_VIA',
            'HTTP_XROXY_CONNECTION',
            'HTTP_PROXY_CONNECTION',
            'REMOTE_ADDR'
        ];

        $addresses = [];
        foreach ($fields as $field) {
            $value = $_SERVER[$field];
            if (!empty($value)) {
                $addresses[] = $value;
            }
        }

        return empty($addresses) ? bin2hex(random_bytes(4)) : serialize($addresses);
    }
}
