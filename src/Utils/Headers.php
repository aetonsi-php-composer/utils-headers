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
    public static function getAuthorizationHeader()
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


    /**
     * Checks if a 200 ok response should instead be a 304 not modified.
     *
     * Adapted and expanded from: https://stackoverflow.com/a/2015665 , https://stackoverflow.com/a/52005477
     *
     * @param string|null $responseData the data to be transmitted to the client. if null, reads the output buffer
     * @param string|null $scriptFilename the script to check for modification time. if null, is $_SERVER['SCRIPT_FILENAME']
     * @param bool $updateHttpsStatusCode if true, if the response is a 304, calls \http_response_code to update the response code
     * @param bool $checkBothTimestampAndHash if true, both the script's modification time and responseData hash should match between server and client,
     *              to be considered a 304. if false, just one match is sufficient
     * @return int correct http response code, 200 or 304
     */
    public static function http200Or304($responseData = null, $scriptFilename = null, $updateHttpStatusCode = true, $checkBothTimestampAndHash = true)
    {
        // preliminary checks
        $responseData = \is_null($responseData) ? \ob_get_contents() : $responseData;
        $scriptFilename = \is_null($scriptFilename) ? $_SERVER['SCRIPT_FILENAME'] : $scriptFilename;
        if (!\file_exists($scriptFilename)) {
            throw new \InvalidArgumentException("\$scriptFilename = $scriptFilename", 500);
        }

        // calculate current server side values and set headers
        $serverTimestamp = \gmdate("D, d M Y H:i:s T", \filemtime($scriptFilename)); // \gmdate('r', \filemtime($scriptFilename));
        $serverHash = \md5($responseData); // \md5(\filemtime($scriptFilename) . $file)
        \header("ETag: \"$serverHash\"");
        \header("Last-Modified: $serverTimestamp");
        \header('Cache-Control: public');

        // check if it's a "304 not modified" or not
        $http_response_code = 200;
        if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) || isset($_SERVER['HTTP_IF_NONE_MATCH'])) {
            // retrieve client side values
            $clientTimestamp = $_SERVER['HTTP_IF_MODIFIED_SINCE'];
            \preg_match('/(W\/|w\/|)(")(.{32})(")/', $_SERVER['HTTP_IF_NONE_MATCH'], $clientHashPortions); // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
            $clientHash = $clientHashPortions[3];

            // check if it's a 304 or not
            $timestampsMatch = $clientTimestamp === $serverTimestamp;
            $hashesMatch = $clientHash === $serverHash;
            $is304 = $checkBothTimestampAndHash ? $timestampsMatch && $hashesMatch : $timestampsMatch || $hashesMatch;
            if ($is304) {
                // set http response code
                $http_response_code = 304;
            }
        }

        // set header and/or return http status code
        if ($updateHttpStatusCode) {
            \http_response_code($http_response_code);
        }
        return $http_response_code;
    }


    /**
     * Uses an output buffer to wrap output and possibly update the status code
     *
     * @return void
     */
    public static function http200Or304Wrapper()
    {
        // wrap output in output buffer
        \ob_start();

        // register shutdown function
        \register_shutdown_function(function () {
            if (\http_response_code() === 200) {
                // if status code is 200, check if it's really a 200 or instead a 304
                if (self::http200Or304() === 200) {
                    // status code still 200, response data differs from client's cache, output it
                    \ob_end_flush();
                } else {
                    // status code updated to 304, client already has up-to-date data, clean buffer and output nothing
                    \ob_clean();
                }
            } else {
                // if status code is something else, just output the response
                \ob_end_flush();
            }
        });
    }
}
