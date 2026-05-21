import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch


os.environ.setdefault('SECRET_KEY', 'test-secret-key')
if 'DATABASE_PATH' not in os.environ:
    _temp_dir = tempfile.mkdtemp(prefix='outlookEmail-cloudflare-tests-')
    os.environ['DATABASE_PATH'] = os.path.join(_temp_dir, 'test.db')

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

web_outlook_app = importlib.import_module('web_outlook_app')


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=''):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.reason = 'OK'

    def json(self):
        return self._payload


class CloudflareCfMailIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app = web_outlook_app.app
        self.app.config['TESTING'] = True
        with self.app.app_context():
            web_outlook_app.init_db()
            self.assertTrue(web_outlook_app.set_setting('cloudflare_worker_domain', 'cf-mail.example.workers.dev'))
            self.assertTrue(web_outlook_app.set_setting('cloudflare_email_domains', 'example.com'))
            self.assertTrue(web_outlook_app.set_setting('cloudflare_api_key', 'cfm-current-key'))
            self.assertTrue(web_outlook_app.set_setting('cloudflare_admin_password', 'legacy-password'))

    def test_cloudflare_create_address_uses_cf_mail_external_mailboxes_api(self):
        response = FakeResponse(201, {
            'mailbox': {
                'id': 42,
                'address': 'demo@example.com',
            },
            'existed': False,
        })

        with self.app.app_context(), patch.object(web_outlook_app.requests, 'post', return_value=response) as post_mock:
            result = web_outlook_app.cloudflare_create_address(username='demo', domain='example.com')

        self.assertTrue(result['success'])
        self.assertEqual(result['address'], 'demo@example.com')
        post_mock.assert_called_once()
        url = post_mock.call_args.args[0]
        kwargs = post_mock.call_args.kwargs
        self.assertEqual(url, 'https://cf-mail.example.workers.dev/api/external/mailboxes')
        self.assertEqual(kwargs['headers']['X-API-Key'], 'cfm-current-key')
        self.assertEqual(kwargs['json'], {'address': 'demo@example.com'})

    def test_cloudflare_get_messages_uses_cf_mail_external_messages_api(self):
        response = FakeResponse(200, {
            'messages': [
                {
                    'id': 7,
                    'mailbox_address': 'demo@example.com',
                    'sender': 'sender@example.net',
                    'subject': 'Code',
                    'text': '123456',
                }
            ],
            'count': 1,
        })

        with self.app.app_context(), patch.object(web_outlook_app.requests, 'get', return_value=response) as get_mock:
            messages = web_outlook_app.cloudflare_get_messages('Demo@Example.com', limit=20, offset=3)

        self.assertEqual(len(messages), 1)
        get_mock.assert_called_once()
        url = get_mock.call_args.args[0]
        kwargs = get_mock.call_args.kwargs
        self.assertEqual(url, 'https://cf-mail.example.workers.dev/api/external/messages')
        self.assertEqual(kwargs['headers']['X-API-Key'], 'cfm-current-key')
        self.assertEqual(kwargs['params'], {
            'address': 'demo@example.com',
            'filter': 'all',
            'limit': 20,
            'offset': 3,
        })

    def test_cloudflare_global_messages_uses_cf_mail_external_messages_api(self):
        response = FakeResponse(200, {
            'messages': [],
            'count': 0,
            'limit': 10,
            'offset': 5,
        })

        with self.app.app_context(), patch.object(web_outlook_app.requests, 'get', return_value=response) as get_mock:
            result = web_outlook_app.cloudflare_get_admin_messages(limit=10, offset=5)

        self.assertTrue(result['success'])
        get_mock.assert_called_once()
        url = get_mock.call_args.args[0]
        kwargs = get_mock.call_args.kwargs
        self.assertEqual(url, 'https://cf-mail.example.workers.dev/api/external/messages')
        self.assertEqual(kwargs['headers']['X-API-Key'], 'cfm-current-key')
        self.assertEqual(kwargs['params'], {
            'filter': 'all',
            'limit': 10,
            'offset': 5,
        })

    def test_cloudflare_delete_address_uses_cf_mail_external_mailboxes_api(self):
        response = FakeResponse(200, {'success': True})

        with self.app.app_context(), patch.object(web_outlook_app.requests, 'delete', return_value=response) as delete_mock:
            deleted = web_outlook_app.cloudflare_delete_address('Demo@Example.com')

        self.assertTrue(deleted)
        delete_mock.assert_called_once()
        url = delete_mock.call_args.args[0]
        kwargs = delete_mock.call_args.kwargs
        self.assertEqual(url, 'https://cf-mail.example.workers.dev/api/external/mailboxes')
        self.assertEqual(kwargs['headers']['X-API-Key'], 'cfm-current-key')
        self.assertEqual(kwargs['params'], {'address': 'demo@example.com'})


if __name__ == '__main__':
    unittest.main()
