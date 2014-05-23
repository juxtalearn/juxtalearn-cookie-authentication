/**
 * Parse JuxtaLearn cookies, and display the user's name etc.
 *
 * IMPORTANT: this is not an "authentication" library.
 * You should protect sensitive pages using the JuxtaLearn_Cookie_Authentication PHP library.
 * @copyright 2014 The Open University.
 */

/*jslint white: true, indent: 2 */
/*global document:false, get_cookie, parse_cookies */

function JXL_Cookie() {

  'use strict';

  var result = parse_cookies();

  function get_property(key) {
    if (!key) { return result; }
    return result && result[key];
  }

  function display_login(selector) {
    var el = document.querySelector(selector);
    if (el && result && result.is_authenticated) {
      el.innerHTML = "Logged in as: " + result.display_name;
    }
  }

  function parse_cookies() {
    var
      ck_user = get_cookie("clipit_user"),
      user_re = /^(\w{10,})\.(\d{9,})\.login=(\w+)\.role=(\w*)\.id=(\d*)$/,
      matches = user_re.exec(ck_user),
      parse_r = { is_authenticated: false };

    if (!matches) { return parse_r; }

    parse_r = {
      is_authenticated: true,
      display_name: get_cookie("clipit_name"),
      api_token:  get_cookie("clipit_token"),
      user_mail:  get_cookie("clipit_mail"),
      user_login: matches[ 3 ],
      user_role:  matches[ 4 ],
      user_id:    matches[ 5 ],
      hash:       matches[ 1 ],
      timestamp:  matches[ 2 ],
      regex:      user_re
    };
    return parse_r;
  }

  function get_cookie(key) {
    //https://developer.mozilla.org/en-US/docs/Web/API/document.cookie
    //document.cookie.replace(/(?:(?:^|.*;\s*)test2\s*\=\s*([^;]*).*$)|^.*$/, "$1");
    var regex = new RegExp("" + key + "\\s*\\=\\s*([^;]*)(.*$|^.*$)"),
      matches = regex.exec(document.cookie);
    return matches && decodeURIComponent(matches[ 1 ]).replace(/\+/g, " ");
  }

  return {
    get_cookie: get_cookie,
    display_login: display_login,
    get: get_property
  };
}
