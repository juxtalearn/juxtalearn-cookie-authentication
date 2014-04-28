<?php
/**
 * TEST.
 */
ini_set('display_errors', 1);
error_reporting(E_ALL);

require 'jl_domain_cookie_auth.php';

define( 'JXL_COOKIE_SECRET_KEY', '54321dcba{ Very long and random }' );
define( 'JXL_COOKIE_DOMAIN', 'localhost' ); //'127.0.0.1' );

//$bok = setcookie('n_test', 'value', 0, '/', null);


test_auth_master_delete_cookies();
$set_result = test_auth_master_set_cookies();
$get_result = test_auth_slave_parse_cookies();


?><h1>TEST: JuxtaLearn_Domain_Cookie_Authentication</h1><pre><?php
var_dump( $set_result, $get_result );


function test_auth_master_delete_cookies() {
    $delete = isset($_GET['delete']);

    $auth = new JuxtaLearn_Domain_Cookie_Authentication();

    if ($delete) {
        $b_ok = $auth->delete_cookies();
        die( 'TEST: deleted cookies' );
    }
}

// Clip-It.
function test_auth_master_set_cookies() {
    $expire = isset($_GET['expire']) ? time() + intval($_GET['expire']) : 0;

    $auth = new JuxtaLearn_Domain_Cookie_Authentication();
    $set_result = null;

    $parse = $auth->parse_cookies();
    //if (!$auth->is_authenticated()) {
        $set_result = $auth->set_required_cookie( 'jdoe', 'teacher', $expire );
        $b_ok = $auth->set_name_cookie( 'John Doe', $expire );
        $b_ok = $auth->set_token_cookie( '0491d9433979a6187a9bc03f868aa104', $expire );
    //}
    return $set_result;
}

// Tricky Topic tool, etc.
function test_auth_slave_parse_cookies() {
    $auth = new JuxtaLearn_Domain_Cookie_Authentication();
    return $auth->parse_cookies();
}


