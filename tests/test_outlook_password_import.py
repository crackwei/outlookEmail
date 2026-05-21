import importlib
import os
import tempfile
import unittest
from unittest.mock import patch


os.environ.setdefault('SECRET_KEY', 'test-secret-key')
if 'DATABASE_PATH' not in os.environ:
    _temp_dir = tempfile.mkdtemp(prefix='outlookEmail-password-import-tests-')
    os.environ['DATABASE_PATH'] = os.path.join(_temp_dir, 'test.db')

web_outlook_app = importlib.import_module('web_outlook_app')


class FakeOAuthResult:
    def __init__(self, success, refresh_token='', error=''):
        self.success = success
        self.refresh_token = refresh_token
        self.error = error


class FakeOutlookPasswordOAuthClient:
    calls = []

    def __init__(self, client_id, redirect_uri, scopes, *, proxy_url='', timeout=60):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.proxy_url = proxy_url
        self.timeout = timeout

    def get_refresh_token(self, email_addr, password):
        self.__class__.calls.append({
            'email': email_addr,
            'password': password,
            'proxy_url': self.proxy_url,
            'timeout': self.timeout,
        })
        if email_addr.startswith('fail'):
            return FakeOAuthResult(False, error='invalid password')
        return FakeOAuthResult(True, refresh_token=f'refresh-{email_addr}')


class OutlookPasswordImportTests(unittest.TestCase):
    def setUp(self):
        self.app = web_outlook_app.app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True

        with self.app.app_context():
            web_outlook_app.init_db()
            db = web_outlook_app.get_db()
            db.execute('DELETE FROM account_aliases')
            db.execute('DELETE FROM account_tags')
            db.execute('DELETE FROM accounts')
            db.execute("DELETE FROM groups WHERE name NOT IN ('默认分组', '临时邮箱')")
            db.commit()
        FakeOutlookPasswordOAuthClient.calls = []

    def test_password_import_parser_accepts_colon_and_triple_dash(self):
        self.assertEqual(
            web_outlook_app.split_outlook_password_import_line('User@Outlook.com:secret'),
            {'email': 'user@outlook.com', 'password': 'secret'},
        )
        self.assertEqual(
            web_outlook_app.split_outlook_password_import_line('user@hotmail.com---secret'),
            {'email': 'user@hotmail.com', 'password': 'secret'},
        )
        self.assertEqual(
            web_outlook_app.split_outlook_password_import_line('user@hotmail.com----secret'),
            {'email': 'user@hotmail.com', 'password': 'secret'},
        )
        self.assertIsNone(web_outlook_app.split_outlook_password_import_line('bad-line'))

    def test_batch_password_import_rotates_proxies_and_returns_failed_credentials(self):
        with self.app.app_context():
            group_id = web_outlook_app.add_group('批量换Token', color='#0078d4')

        with patch.object(web_outlook_app, 'OutlookPasswordOAuthClient', FakeOutlookPasswordOAuthClient):
            response = self.client.post('/api/accounts/import-outlook-passwords', json={
                'account_string': '\n'.join([
                    'ok1@outlook.com:pass1',
                    'fail@outlook.com---pass2',
                    'bad-line',
                    'ok2@hotmail.com----pass3',
                ]),
                'proxy_list': 'http://127.0.0.1:8080\nsocks5://127.0.0.1:1080',
                'group_id': group_id,
                'forward_enabled': True,
                'timeout': 30,
            })

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['processed_count'], 3)
        self.assertEqual(payload['token_success_count'], 2)
        self.assertEqual(payload['added_count'], 2)
        self.assertEqual(payload['failed_count'], 1)
        self.assertEqual(payload['invalid_count'], 1)
        self.assertEqual(payload['failed_accounts'][0]['email'], 'fail@outlook.com')
        self.assertEqual(payload['failed_accounts'][0]['password'], 'pass2')

        self.assertEqual(
            [call['proxy_url'] for call in FakeOutlookPasswordOAuthClient.calls],
            ['http://127.0.0.1:8080', 'socks5://127.0.0.1:1080', 'http://127.0.0.1:8080'],
        )

        with self.app.app_context():
            ok1 = web_outlook_app.get_account_by_email('ok1@outlook.com')
            ok2 = web_outlook_app.get_account_by_email('ok2@hotmail.com')

        self.assertEqual(ok1['password'], 'pass1')
        self.assertEqual(ok1['refresh_token'], 'refresh-ok1@outlook.com')
        self.assertTrue(ok1['forward_enabled'])
        self.assertEqual(ok2['password'], 'pass3')
        self.assertEqual(ok2['group_id'], group_id)


if __name__ == '__main__':
    unittest.main()
