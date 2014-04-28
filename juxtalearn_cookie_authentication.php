<?php
// Demo/ draft only - NOT PRODUCTION READY.
/**
 * Basic domain cookie creation and authentication. Needs encapsulating in a class.
 * Validate the PHP: http://writecodeonline.com/php/
 * @author Nick Freear, 25 April 2014
 */
date_default_timezone_set( 'GMT' );


function set_clipit_domain_cookies() {
    $shared_secret_key = '54321dcba{ Very long and random }';
    $domain = '.juxtalearn.org';

    $api_token = '0491d9433979a6187a9bc03f868aa104';
    $user_id = 'jdoe';
    $display_name = 'John Doe';
    $user_role = 'teacher';
    $expires_timestamp = time() + 60 * 60 * 24 * 1;  // Expire in 1 day - Clip-It can vary this.
    $expires_formatted = cookie_date($expires_timestamp);

    $user_cookie_payload = user_cookie_payload( $user_id, $display_name, $user_role, $expires_timestamp );

    $user_cookie_value = generate_cookie_hash( $expires_timestamp, $user_cookie_payload, $shared_secret_key ) . $user_cookie_payload;

    $b_ok = setcookie( 'clipit_token', $api_token, $expires_timestamp, '/', $domain );
    $b_ok = setcookie( 'clipit_user', $user_cookie_value, $expires_timestamp, '/', $domain );

    var_dump( $user_cookie_value, $expires_formatted, $shared_secret_key );  // Debug.

    return $b_ok;
}
set_clipit_domain_cookies();


function parse_clipit_domain_cookies() {
    $shared_secret_key = '54321dcba{ Very long and random }';
    $domain = '.juxtalearn.org';

    var_dump( $_COOKIE );  // Debug.

    $result = array( 'authenticated' => false );

    // Try a basic check.
    if (!isset($_COOKIE['clipit_token']) || !isset($_COOKIE['clipit_user'])) {
        $result['msg'] = 'Warning, missing required cookies';
        return $result;
    }
 
    // Try to extract data.
    if (!preg_match( '/^(\w+)\.user_id=(\w+)\.display=([\w ]+)\.role=(\w+)\.expires=(\d+)$/', $_COOKIE['clipit_user'], $m)) {
        $result['msg'] = 'Error, unexpected cookie format.';
        return $result;
    }

    $result = array(
        'authenticated' => false,  // Still false!
        'clipit_api_token' => $_COOKIE['clipit_token'],
        'clipit_user_raw' => $m[0],
        'hash' => $m[1],
        'user_id' => $m[2],
        'display_name' => $m[3],
        'user_role' => $m[4],
        'expires_timestamp' => $m[5],
        'expires_formatted' => cookie_date( $m[5] ),
    );

    // Try validation.
    $payload = user_cookie_payload( $result['user_id'], $result['display_name'], $result['expires'] );
    $try_hash = generate_cookie_hash( $result['expires'], $payload, $shared_secret_key );

    if ($try_hash != $result['hash']) {
        // ERROR.
        return array( 'authenticated' => false, 'msg' => 'Error, invalid cookie.' ); 
    }

    $result['msg'] = 'Success';
    $result['authenticated'] = true;

    return $result;
}
$result = parse_clipit_domain_cookies();

var_dump( $result );  // Debug.

// Utilities.
function generate_cookie_hash( $expires_timestamp, $payload, $shared_key ) {
    return md5( $shared_key . $expires_timestamp . $payload );
}

function user_cookie_payload( $user_id, $display_name, $user_role, $expires_timestamp ) {
    $SEP = '.';
    return $SEP . 'user_id=' . $user_id . $SEP . 'display=' . $display_name . $SEP . 'role=' . $user_role . $SEP . 'expires=' . $expires_timestamp;
}

function cookie_date( $timestamp ) {
    return date( 'l, j F Y H:i:s', $timestamp );
}
