<?php
/**
 * Basic domain cookie creation and authentication.
 * Validate the PHP: http://writecodeonline.com/php
 *
 * @author Nick Freear, 25 April 2014.
 * @link   https://gist.github.com/nfreear/9b3431b75a843e839f3c
 */
date_default_timezone_set( 'GMT' );


class JuxtaLearn_Cookie_Auth {

    const DEF_SECRET_KEY    = 'JXL_COOKIE_SECRET_KEY';
    const DEF_COOKIE_DOMAIN = 'JXL_COOKIE_DOMAIN';

    const COOKIE_TOKEN = 'clipit_token';
    const COOKIE_USER  = 'clipit_user';

    const COOKIE_FORMAT = '%hash.user_id=%userid.display=%display.role=%role.time=%time';
    const COOKIE_FORMAT_S = '%s.user_id=%s.display=%s.role=%s.time=%d';
    const COOKIE_REGEX  =
      '/^(\w+)\.user_id=(\w+)\.display=([\w ]+)\.role=(\w+)\.time=(\d+)$/';

    private $shared_secret_key;
    protected $cookie_domain;

    public function __construct($shared_secret_key, $cookie_domain = '.juxtalearn.org') {
        $this->shared_secret_key = $shared_secret_key;
        $this->cookie_domain = $cookie_domain;
    }

    /**
     * This is called by Clip-It (authentication master), to set cookies.
     * @return array  Debug information, including input parameters.
     */
    function set_cookies( $user_id, $display_name, $user_role = 'student',
        $api_token = '0491d9433979a6187a9bc03f868aa104', $expires = FALSE ) {

        $timestamp = time();
        $payload = $this->user_payload(
             $user_id, $display_name, $user_role, $timestamp );

        $user_cookie = $this->make_cookie_hash( $timestamp, $payload ) . $payload;

        return array(
            'token_cookie_ok' => setcookie(
                self::COOKIE_TOKEN, $api_token, $expires, '/', $this->cookie_domain ),
            'user_cookie_ok' => setcookie(
                self::COOKIE_USER, $user_cookie, $expires, '/', $this->cookie_domain ),
            'token_cookie_value' => $api_token,
            'user_cookie_value' => $user_cookie,
            'cookie_domain' => $this->cookie_domain,
            'cookie_path' => '/',
            'user_id' => $user_id,
            'display_name' => $display_name,
            'user_role' => $user_role,
            'api_token' => $api_token,  //AKA, 'token_cookie_value'
            'expires' => $expires,
            'time' => $timestamp,
            'time_formatted' => $this->cookie_date( $timestamp ),
        );
    }

    /**
     * Called by Tricky Topic tool etc.
     * @return array  Flag indicating if authentication succeeded, user data, debug info.
     */
    public function parse_cookies() {
        $result = array( 'is_authenticated' => false );
 
        // Try a basic check.
        if (!isset($_COOKIE[self::COOKIE_TOKEN]) || !isset($_COOKIE[self::COOKIE_USER])) {
            $result['msg'] = 'Warning, missing required cookies';
            return $result;
        }

        // Try to extract data.
        if (!preg_match( self::COOKIE_REGEX, $_COOKIE[self::COOKIE_USER], $m )) {
            $result['msg'] = 'Error, unexpected cookie format.';
            return $result;
        }

        $result = array(
            'is_authenticated' => false,  // Still false!
            'token_cookie_value' => $_COOKIE[self::COOKIE_TOKEN],
            'user_cookie_value' => $m[0],
            'hash' => $m[1],
            'user_id' => $m[2],
            'display_name' => $m[3],
            'user_role' => $m[4],
            'api_token' => $_COOKIE[self::COOKIE_TOKEN],
            'time' => $m[5],
            'time_formatted' => $this->cookie_date( $m[5] ),
        );

        // Try to validate.
        $payload = $this->user_payload(
            $result['user_id'], $result['display_name'], $result['time'] );
        $try_hash = $this->make_cookie_hash( $result['time'], $payload );

        if ($try_hash != $result['hash']) {
            // ERROR.
            return array( 'is_authenticated' => false, 'msg' => 'Error, invalid cookie.' ); 
        }

        $result['msg'] = 'Success';
        $result['is_authenticated'] = true;

        return $result;
    }


    // Utilities.
    protected function make_cookie_hash( $timestamp, $payload ) {
        return md5( $this->shared_secret_key . $timestamp . $payload );
    }

    function user_payload( $user_id, $display_name, $role, $timestamp ) {
        return strtr( self::COOKIE_FORMAT, array( '%hash' => '', '%userid' => $user_id,
            '%display' => $display_name, '%role' => $role, '%time' => $timestamp ));

        #return sprintf(self::COOKIE_FORMAT, '', $user_id, $display_name, $role, $timestamp);
        # Legacy.
        #$SEP = '.';
        #return $SEP . 'user_id=' . $user_id . $SEP . 'display=' . $display_name . $SEP . 'role=' . $role . $SEP . 'created=' . $timestamp;
    }

    protected function cookie_date( $timestamp ) {
        return date( 'l, j F Y H:i:s', $timestamp );
    }
}


// TEST.
$auth = new JuxtaLearn_Cookie_Auth('54321dcba{ Very long and random }');

$set_result = $auth->set_cookies(
    'jdoe', 'John Doe', 'teacher', '0491d9433979a6187a9bc03f868aa104' );
$get_result = $auth->parse_cookies();

var_dump( $set_result, $get_result );


#End.