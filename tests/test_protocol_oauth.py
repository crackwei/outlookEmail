import unittest

from outlook_web.protocol_oauth import (
    extract_html_redirect_url,
    extract_microsoft_error,
    is_login_auto_post_interstitial,
    OutlookPasswordOAuthClient,
    parse_login_form,
)


class ProtocolOAuthParsingTests(unittest.TestCase):
    def test_parse_login_form_reads_microsoft_config_token_and_action(self):
        page = r'''
        <html>
          <head><title>登录到您的帐户</title></head>
          <script>
            var $Config = {
              "urlPost": "https:\/\/login.microsoftonline.com\/common\/login",
              "sFT": "token\u0026value",
              "sFTName": "flowToken",
              "sCtx": "ctx-value",
              "canary": "canary-value"
            };
          </script>
        </html>
        '''

        inputs, action = parse_login_form(page)

        self.assertEqual(action, 'https://login.microsoftonline.com/common/login')
        self.assertEqual(inputs['flowToken'], 'token&value')
        self.assertEqual(inputs['ctx'], 'ctx-value')
        self.assertEqual(inputs['canary'], 'canary-value')

    def test_parse_login_form_reads_sft_tag_ppft(self):
        page = r'''
        <html>
          <script>
            var Config = {
              "urlPost": "https:\/\/login.live.com\/ppsecure\/post.srf",
              "sFTTag": "<input type=\"hidden\" name=\"PPFT\" value=\"ppft-token\"\/>"
            };
          </script>
        </html>
        '''

        inputs, action = parse_login_form(page)

        self.assertEqual(action, 'https://login.live.com/ppsecure/post.srf')
        self.assertEqual(inputs['PPFT'], 'ppft-token')

    def test_parse_login_form_reads_o_post_params_flow_token(self):
        page = r'''
        <html>
          <head><title>正在重定向</title></head>
          <meta name="PageID" content="BssoInterrupt" />
          <script>
            var $Config = {
              "oPostParams": {
                "flowToken": "flow-token",
                "ctx": "ctx-value",
                "loginfmt": "user@example.com",
                "type": "11",
                "LoginOptions": "3"
              },
              "browser": {"type": "chrome"},
              "urlPost": "\/common\/login?client-request-id=abc\u0026sso_reload=True"
            };
          </script>
        </html>
        '''

        inputs, action = parse_login_form(page)

        self.assertEqual(action, '/common/login?client-request-id=abc&sso_reload=True')
        self.assertEqual(inputs['flowToken'], 'flow-token')
        self.assertEqual(inputs['ctx'], 'ctx-value')
        self.assertEqual(inputs['loginfmt'], 'user@example.com')
        self.assertEqual(inputs['type'], '11')
        self.assertTrue(is_login_auto_post_interstitial(page))

    def test_redirect_page_uses_config_urlpost(self):
        page = r'''
        <html>
          <head><title>正在重定向</title></head>
          <script>
            var $Config = {
              "urlPost": "\/common\/oauth2\/v2.0\/authorize?client_id=abc\u0026sso_reload=true"
            };
          </script>
        </html>
        '''

        self.assertEqual(
            extract_html_redirect_url(page),
            '/common/oauth2/v2.0/authorize?client_id=abc&sso_reload=true',
        )

    def test_sign_in_page_does_not_follow_noscript_jsdisabled_refresh(self):
        page = '''
        <html>
          <head><title>登录到您的帐户</title></head>
          <noscript>
            <meta http-equiv="Refresh" content="0; URL=/jsdisabled">
          </noscript>
          <script>
            var $Config = {"urlPost": "https://login.microsoftonline.com/common/login"};
          </script>
        </html>
        '''

        self.assertEqual(extract_html_redirect_url(page), '')

    def test_extract_microsoft_error_reads_config_message(self):
        page = r'''
        <html>
          <meta name="PageID" content="ConvergedError" />
          <script>
            var $Config = {
              "strMainMessage": "我们收到了错误的请求。",
              "strServiceExceptionMessage": "AADSTS900561: The endpoint only accepts POST requests."
            };
          </script>
        </html>
        '''

        self.assertIn('AADSTS900561', extract_microsoft_error(page))

    def test_follow_login_interstitial_posts_instead_of_following_redirect_get(self):
        class FakeResponse:
            def __init__(self, text, url='https://login.microsoftonline.com/common/login', status_code=200):
                self.text = text
                self.url = url
                self.status_code = status_code
                self.headers = {}

        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.proxies = {}
                self.posts = []
                self.gets = []

            def post(self, url, data=None, timeout=None, allow_redirects=None):
                self.posts.append({
                    'url': url,
                    'data': data or {},
                    'allow_redirects': allow_redirects,
                })
                return FakeResponse(r'''
                <html>
                  <meta name="PageID" content="ConvergedSignIn" />
                  <script>
                    var $Config = {
                      "sFT": "password-token",
                      "sFTName": "flowToken",
                      "urlPost": "https:\/\/login.microsoftonline.com\/common\/login"
                    };
                  </script>
                </html>
                ''')

            def get(self, url, timeout=None, allow_redirects=None):
                self.gets.append(url)
                raise AssertionError('BSSO interstitial must not be followed with GET')

        bsso_page = r'''
        <html>
          <head><title>正在重定向</title></head>
          <meta name="PageID" content="BssoInterrupt" />
          <script>
            var $Config = {
              "oPostParams": {
                "flowToken": "interstitial-token",
                "ctx": "ctx-value",
                "loginfmt": "user@example.com",
                "type": "ChromeSsoTelemetry"
              },
              "urlPost": "\/common\/login?client-request-id=abc\u0026sso_reload=True"
            };
          </script>
        </html>
        '''

        fake_session = FakeSession()
        client = OutlookPasswordOAuthClient(
            'client-id',
            'http://localhost:8080',
            ['offline_access'],
            session=fake_session,
        )

        response = client._follow_login_interstitials(FakeResponse(bsso_page), 'user@example.com')
        inputs, action = parse_login_form(response.text)

        self.assertEqual(len(fake_session.posts), 1)
        self.assertEqual(fake_session.posts[0]['allow_redirects'], False)
        self.assertEqual(fake_session.posts[0]['data']['flowToken'], 'interstitial-token')
        self.assertEqual(fake_session.posts[0]['data']['ctx'], 'ctx-value')
        self.assertEqual(inputs['flowToken'], 'password-token')
        self.assertTrue(action)


if __name__ == '__main__':
    unittest.main()
