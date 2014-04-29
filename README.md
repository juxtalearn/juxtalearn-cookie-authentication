# JuxtaLearn domain cookie authentication library

Project:

* [JuxtaLearn: Tricky Topic tool](http://juxtalearn.net)
* [JuxtaLearn: project, and ClipIt](http://juxtalearn.org)
* [GitHub: JuxtaLearn code](https://github.com/juxtalearn)
* [GitHub: IET-OU code][ou-jxl]

## Usage - authentication provider or master:

    <?php
    define( 'JXL_COOKIE_SECRET_KEY', '54321{ long, random and shared }' );
    
    $auth = new JuxtaLearn_Cookie_Authentication();
    $auth->set_required_cookie( 'johndoe', 'teacher' );

## Usage - authentication consumer or slave:

    <?php
    define( 'JXL_COOKIE_SECRET_KEY', '54321{ long, random and shared }' );
    
    $auth = new JuxtaLearn_Cookie_Authentication();
    $result = $auth->parse_cookies();
    if ($auth->is_authenticated()) {
        var_dump( $result[ 'user_login' ] );
        //...
    }

[ou-jxl]: https://github.com/IET-OU/oer-evidence-hub-org/tree/quiz/CR1/scaffold
[End]: http://example