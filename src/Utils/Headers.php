<?php

namespace Aetonsi\Utils;

class Headers
{
    /**
     * Returns the value of the http Authorization header if present, or else null
     *
     * Adapted from: https://gist.github.com/wildiney/b0be69ff9960642b4f7d3ec2ff3ffb0b
     *
     * @return string|null Authorization header or null
     */
    public static function getAuthorizationHeader() // TODO move to github and include via composer
    {
        $header = null;
        if (isset($_SERVER['Authorization'])) {
            $header = \trim($_SERVER["Authorization"]);
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $header = \trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (\function_exists('apache_request_headers')) {
            $requestHeaders = \apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = \array_combine(\array_map('ucwords', \array_keys($requestHeaders)), \array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $header = \trim($requestHeaders['Authorization']);
            }
        }
        return $header;
    }

    /**
     * Returns the value of the Bearer token if present, or else null
     *
     * Adapted from: https://gist.github.com/wildiney/b0be69ff9960642b4f7d3ec2ff3ffb0b
     *
     * @return string|null Bearer token value
     */
    public static function getBearerToken()
    {
        $header = self::getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($header)) {
            if (\preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
}
