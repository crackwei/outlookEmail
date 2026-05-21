import unittest

from outlook_web.protocol_oauth import extract_html_redirect_url, parse_login_form


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


if __name__ == '__main__':
    unittest.main()
