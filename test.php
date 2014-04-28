<?php
// ====================================
// TEST.
ini_set('display_errors', 1);
error_reporting(E_ALL);

require 'jl_domain_cookie_auth.php';


define( 'JXL_COOKIE_SECRET_KEY', '54321dcba{ Very long and random }' );
define( 'JXL_COOKIE_DOMAIN', 'localhost' ); //'127.0.0.1' );

//$bok = setcookie('n_test', 'value', 0, '/', null);


$expire = isset($_GET['expire']) ? intval($_GET['expire']) : 0;
$delete = isset($_GET['delete']);

$auth = new JuxtaLearn_Domain_Cookie_Authentication();

if ($delete) {
    $auth->delete_cookies();
    exit;
}

$set_result;

// Clip-It
$clipit = $auth->parse_cookies();
//if (!$auth->is_authenticated()) {
    $set_result = $auth->set_required_cookie( 'jdoe', 'teacher', $expire );
    $b_ok = $auth->set_name_cookie( 'John Doe', $expire );
    $b_ok = $auth->set_token_cookie( '0491d9433979a6187a9bc03f868aa104', $expire );
//}

// Tricky Topic tool, etc.
$get_result = $auth->parse_cookies();

echo '<pre>';
var_dump( $set_result, $get_result );

