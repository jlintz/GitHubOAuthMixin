# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import urllib
import logging
import tornado.auth
from tornado import httpclient
from tornado import escape
"""
Example Usage:

class GithubHandler(BaseHandler, GithubMixin):
    @tornado.web.asynchronous
    def get(self):
        logging.info(self.request)
        if self.get_argument("code", None):
            self.get_authenticated_user(
                client_id=self.settings["client_id"],
                client_secret=self.settings["client_secret"],
                redirect_uri=self.settings["redirect_uri"],
                code=self.get_argument("code"),
                callback=self.async_callback(self._on_auth)
        )
            return

        if self.get_argument("error", None):
            raise tornado.web.HTTPError(403, self.get_argument("error"))

        self.authorize_redirect(
            client_id=self.settings["client_id"],
            client_secret=self.settings["client_secret"],
            redirect_uri=self.settings["redirect_uri"],
           extra_params={ "scope": "repo" }
        )

    def _on_auth(self, user):
        logging.info(user)
        if not user:
            raise tornado.web.HTTPError(500, "GitHub auth failed")
        self.set_secure_cookie("user", escape.json_encode(user))
        self.redirect("/")

"""


class GithubMixin(tornado.auth.OAuth2Mixin):

    _OAUTH_ACCESS_TOKEN_URL = "http://github.com/login/oauth/access_token"
    _OAUTH_AUTHORIZE_URL = "http://github.com/login/oauth/authorize"
    _OAUTH_NO_CALLBACKS = False

    def get_authenticated_user(self, redirect_uri, client_id,
                               client_secret, code, callback):
        http = httpclient.AsyncHTTPClient()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        fields = set(['login'])

        http.fetch(self._oauth_request_token_url(**args),
          self.async_callback(self._on_access_token, redirect_uri, client_id,
                              client_secret, callback, fields))

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         callback, fields, response):
        if response.error:
            logging.warning('Github auth error: %s' % str(response))
            callback(None)
            return

        args = escape.parse_qs_bytes(escape.native_str(response.body))
        session = {
            "access_token": args["access_token"][-1],
        }

        self.github_request(
            path="/user",
            callback=self.async_callback(
                self._on_get_user_info, callback, session, fields),
            access_token=session["access_token"],
            fields=",".join(fields)
        )

    def _on_get_user_info(self, callback, session, fields, user):
        if user is None:
            callback(None)
            return

        fieldmap = {}
        for field in fields:
            fieldmap[field] = user.get(field)

        fieldmap.update({"access_token": session["access_token"]})
        callback(fieldmap)

    def github_request(self, path, callback, access_token=None,
                           post_args=None, **args):
        url = "https://api.github.com" + path
        all_args = {}
        if access_token:
            all_args["access_token"] = access_token
            all_args.update(args)
            all_args.update(post_args or {})
        if all_args:
            url += "?" + urllib.urlencode(all_args)
        callback = self.async_callback(self._on_github_request, callback)
        http = httpclient.AsyncHTTPClient()
        if post_args is not None:
            http.fetch(url, method="POST", body=urllib.urlencode(post_args),
                       callback=callback)
        else:
            http.fetch(url, callback=callback)

    def _on_github_request(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error,
                            response.request.url)
            callback(None)
            return
        callback(escape.json_decode(response.body))
