/**
 * Parse JuxtaLearn cookies, and display the user's name etc.
 *
 * IMPORTANT: this is not an "authentication" library.
 * You should protect sensitive pages with the JuxtaLearn_Cookie_Authentication PHP library.
 */

var JXL_cookies = JXL_cookies || {};

(function () {

  var
    JC = JXL_cookies;
    result;

  JC.display_login = function (selector) {
    var el = document.querySelector(selector);
    if (el && result && result.is_authenticated) { 
      el.innerHTML = "Logged in as: " + result.display_name;
    }
  }

  JC.get_cookie = function (name) {
      //https://developer.mozilla.org/en-US/docs/Web/API/document.cookie
      //document.cookie.replace(/(?:(?:^|.*;\s*)test2\s*\=\s*([^;]*).*$)|^.*$/, "$1");
      var regex = new RegExp("" + name + "\s*\=\s*([^;]*)(.*$|^.*$)"),
        matches = regex.exec(document.cookie);

      //console.log(regex.exec(document.cookie));
      return matches && decodeURIComponent(matches[ 1 ]).replace(/\+/g, " ");
  }

  JC.parse_cookies = function () {
    var
      ck_user = JC.get_cookie("clipit_user"),
      ck_name = JC.get_cookie("clipit_name"),
      ck_token= JC.get_cookie("clipit_token"),
      user_re = /^(\w{10,})\.(\d{9,})\.login=(\w+)\.role=(\w*)\.id=(\d*)$/,
      matches = user_re.exec(ck_user);

    result = { is_authenticated: false };

    //console.log(ck_user, user_re.exec(ck_user));

    if (!matches) return result;

    result = {
      is_authenticated: true,
      display_name: ck_name,
      api_token:  ck_token,
      user_login: matches[ 3 ],
      user_role:  matches[ 4 ],
      user_id:    matches[ 5 ],
      hash:       matches[ 1 ],
      timestamp:  matches[ 2 ],
      regex:      user_re
    };
	return result;
  }

})();

