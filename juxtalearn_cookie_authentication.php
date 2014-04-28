<?php
/**
 * Basic domain cookie creation and authentication.
 * Validate the PHP: http://writecodeonline.com/php
 *
 * @author Nick Freear, 25 April 2014.
 * @link   https://gist.github.com/nfreear/9b3431b75a843e839f3c
 */
/* Questions:
  - What is the maximum length of the user name, and what can it contain?
*/
date_default_timezone_set( 'GMT' );


class JuxtaLearn_Domain_Cookie_Authentication {

    const DF_KEY    = 'JXL_COOKIE_SECRET_KEY';
    const DF_DOMAIN = 'JXL_COOKIE_DOMAIN';

    const COOKIE_TOKEN = 'clipit_token';
    const COOKIE_USER  = 'clipit_user';
    const COOKIE_NAME  = 'clipit_name';

    const COOKIE_FORMAT = '%hash.uid=%userid.role=%role.time=%time';
    const COOKIE_FORMAT_SP = '%s.uid=%s.role=%s.time=%d';
    const COOKIE_REGEX  = '/^(\w+)\.uid=(\w+)\.role=(\w+)\.time=(\d+)$/';

    private $shared_secret_key;
    protected $cookie_domain;
    protected $is_authenticated = FALSE;


    /**
     * The shared secret key and cookie domain can either be set as parameters to the constructor, 
     *
     * @useby auth-master
     * @useby auth-slave 
     */
    public function __construct( $secret_key = NULL, $cookie_domain = NULL ) {
        $this->shared_secret_key = $secret_key ? $secret_key : constant(self::DF_KEY);
        $this->cookie_domain = $cookie_domain ? $cookie_domain : constant(self::DF_DOMAIN);

        if (!$this->cookie_domain) {
            $this->cookie_domain = '.juxtalearn.org';
        }
        if ('localhost' == $this->cookie_domain) {
            $this->cookie_domain = NULL;
        }
    }

    /**
     * @useby auth-master
     */
    public function set_token_cookie( $api_token = '0491d9433979a6187a9bc03f868aa104', $expire = 0 ) {
        return setcookie(
            self::COOKIE_TOKEN, $api_token, $expire, '/', $this->cookie_domain );
    }

    /**
     * @useby auth-master
     */
    public function set_name_cookie( $display_name, $expire = 0 ) {
        return setcookie(
             self::COOKIE_NAME, $display_name, $expire, '/', $this->cookie_domain );
    }

    /**
     * Called by Clip-It (authentication master), to set authentication cookies.
     *
     * @return array  Debug information, including input parameters.
     * @useby auth-master
     */
    public function set_required_cookie( $user_id, $user_role = 'student', $expire = 0 ) {
        $timestamp = time();
        $payload = $this->user_payload( $user_id, $user_role, $timestamp );
        $user_cookie = $this->make_cookie_hash( $timestamp, $payload ) . $payload;

        return array(
            'user_cookie_ok' => setcookie(
                self::COOKIE_USER, $user_cookie, $expire, '/', $this->cookie_domain ),
            'user_cookie_value' => $user_cookie,
            'user_cookie_size' => strlen($user_cookie),
            'cookie_domain' => $this->cookie_domain,
            'cookie_path' => '/',
            'user_id' => $user_id,
            'user_role' => $user_role,
            'expire' => $expire,
            'time' => $timestamp,
            'time_formatted' => $this->cookie_date( $timestamp ),
        );
    }

    /**
     * @useby auth-master
     */
    public function delete_cookies() {
        if (isset( $_COOKIE[self::COOKIE_USER] )) {
            unset( $_COOKIE[self::COOKIE_USER] );
            unset( $_COOKIE[self::COOKIE_NAME] );
            unset( $_COOKIE[self::COOKIE_TOKEN] );
            $expire = time() - 3600;
            setcookie( self::COOKIE_NAME, '', $expire, '/', $this->cookie_domain );
            setcookie( self::COOKIE_TOKEN, '', $expire, '/', $this->cookie_domain );
            return setcookie( self::COOKIE_USER, '', $expire, '/', $this->cookie_domain );
        }
        return NULL;
    }

    /**
     * Called by Tricky Topic tool etc. (authentication slave), to get authentication data
     *
     * @return array  Flag indicating if authentication succeeded, user data, debug info.
     * @useby auth-slave
     */
    public function parse_cookies() {
        $result = array( 'is_authenticated' => false );
 
        // Try a basic check.
        if (!isset($_COOKIE[self::COOKIE_USER])) {  #!isset($_COOKIE[self::COOKIE_TOKEN]) ||
            $result['msg'] = 'Warning, missing authentication cookie.';
            return $result;
        }

        // Try to extract data.
        if (!preg_match( self::COOKIE_REGEX, $_COOKIE[self::COOKIE_USER], $m )) {
            $result['msg'] = 'Error, unexpected user-cookie format.';
            return $result;
        }

        $token_cookie = isset($_COOKIE[self::COOKIE_TOKEN]) ? $_COOKIE[self::COOKIE_TOKEN] : NULL;
        $name_cookie = isset($_COOKIE[self::COOKIE_NAME]) ? $_COOKIE[self::COOKIE_NAME] : NULL;

        $result = array(
            'is_authenticated' => false,  // Still false!
            'token_cookie_value' => $token_cookie,
            'user_cookie_value' => $m[0],
            'hash' => $m[1],
            'user_id' => $m[2],
            'user_role' => $m[3],
            'display_name' => $name_cookie,
            'api_token' => $token_cookie,
            'time' => $m[4],
            'time_formatted' => $this->cookie_date( $m[4] ),
        );

        // Try to validate.
        $payload = $this->user_payload(
            $result['user_id'], $result['user_role'], $result['time'] );
        $try_hash = $this->make_cookie_hash( $result['time'], $payload );

        if ($try_hash != $result['hash']) {
            // ERROR.
            return array( 'is_authenticated' => false, 'msg' => 'Error, invalid cookie.',
                'regex_matches' => $m, 'regex' => self::COOKIE_REGEX ); 
        }

        $result['msg'] = 'Success';
        $result['is_authenticated'] = $this->is_authenticated = true;

        return $result;
    }

    /**
     * @useby auth-master
     * @useby auth-slave 
     */
    public function is_authenticated() {
        return $this->is_authenticated;
    }


    // ==========================================
    // Utilities.

    protected function make_cookie_hash( $timestamp, $payload ) {
        return md5( $this->shared_secret_key . $timestamp . $payload );  #substr(?, 0, 28 );
    }

    function user_payload( $user_id, $role, $timestamp ) {
        return strtr( self::COOKIE_FORMAT, array( '%hash' => '', '%userid' => $user_id,
            '%role' => $role, '%time' => $timestamp ));
    }

    protected function cookie_date( $timestamp ) {
        return date( 'l, j F Y H:i:s', $timestamp );
    }
}


return;
// ====================================
// TEST.

define( 'JXL_COOKIE_SECRET_KEY', '54321dcba{ Very long and random }' );

$auth = new JuxtaLearn_Domain_Cookie_Authentication();

$set_result = $auth->set_cookies(
    'jdoe', 'John Doe', 'teacher', '0491d9433979a6187a9bc03f868aa104' );

$get_result = $auth->parse_cookies();

var_dump( $set_result, $get_result );


#End.