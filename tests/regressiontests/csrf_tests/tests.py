# -*- coding: utf-8 -*-

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.test import TestCase
from django.views.decorators.csrf import csrf_exempt
from django.test.utils import override_settings

settings.DEBUG = True


# Response/views used for CsrfResponseMiddleware and CsrfViewMiddleware tests
def post_form_response():
    resp = HttpResponse(content=u"""
<html><body><h1>\u00a1Unicode!<form method="post"><input type="text" /></form></body></html>
""", mimetype="text/html")
    return resp

def post_form_view(request):
    """A view that returns a POST form (without a token)"""
    return post_form_response()

# Response/views used for template tag tests

class TestingHttpRequest(HttpRequest):
    """
    A version of HttpRequest that allows us to change some things
    more easily
    """
    def is_secure(self):
        return getattr(self, '_is_secure_override', False)

class CsrfViewMiddlewareTest(TestCase):
    # The csrf token is potentially from an untrusted source, so could have
    # characters that need dealing with.
    _csrf_id_cookie = b"<1>\xc2\xa1"
    _csrf_id = "1"

    def _get_GET_no_headers_request(self):

        return TestingHttpRequest()

    def _get_GET_request(self):
        req = TestingHttpRequest()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_REFERER'] = 'http://www.example.com'

        return req

    def _get_POST_request(self):
        req = self._get_GET_request()
        req.method = "POST"

        return req

    def _get_POST_no_headers_request(self):
        req = self._get_GET_no_headers_request()
        req.method = "POST"
        return req

    def _get_POST_request_with_headers(self):
        req = self._get_POST_request()
        return req

    def test_process_request_no_headers_exempt_view(self):
        """
        Check that if a CSRF cookie is present and no token, but the csrf_exempt
        decorator has been applied to the view, the middleware lets it through
        """
        req = self._get_POST_request()
        req2 = CsrfViewMiddleware().process_view(req, csrf_exempt(post_form_view), (), {})
        self.assertEqual(None, req2)

    def test_put_and_delete_rejected(self):
        """
        Tests that HTTP PUT and DELETE methods have protection
        """
        req = TestingHttpRequest()
        req.method = 'PUT'
        req.HTTP_REFERER = 'http://www.evil.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(403, req2.status_code)

        req = TestingHttpRequest()
        req.HTTP_REFERER = 'http://www.evil.com'
        req.method = 'DELETE'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(403, req2.status_code)

    def test_put_and_delete_allowed(self):
        """
        Tests that HTTP PUT and DELETE methods can get through with
        X-CSRFToken and a cookie
        """
        req = self._get_GET_request()
        req.method = 'PUT'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

        req = self._get_GET_request()
        req.method = 'DELETE'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    def test_https_bad_referer(self):
        """
        Test that a POST HTTPS request with a bad referer is rejected
        """
        req = self._get_POST_request_with_headers()
        req._is_secure_override = True
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_REFERER'] = 'https://www.evil.org/somepage'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertNotEqual(None, req2)
        self.assertEqual(403, req2.status_code)

    def test_https_good_referer(self):
        """
        Test that a POST HTTPS request with a good referer is accepted
        """
        req = self._get_POST_request_with_headers()
        req._is_secure_override = True
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_REFERER'] = 'https://www.example.com/somepage'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    def test_https_good_referer_2(self):
        """
        Test that a POST HTTPS request with a good referer is accepted
        where the referer contains no trailing slash
        """
        # See ticket #15617
        req = self._get_POST_request_with_headers()
        req._is_secure_override = True
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_REFERER'] = 'https://www.example.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    @override_settings(PERMITTED_DOMAINS=['www.example.com'])
    def test_good_origin_header(self):
        """
        Test if a good origin header is accepted for across subdomain settings.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_ORIGIN'] = 'http://www.example.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    @override_settings(PERMITTED_DOMAINS=['example.com'])
    def test_good_origin_header_3(self):
        """
        Test if a good origin header is accepted for a no subdomain.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'example.com'
        req.META['HTTP_ORIGIN'] = 'http://example.com'
        req.META['HTTP_REFERER'] = 'http://example.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    def test_good_origin_header_4(self):
        """
        Test if a good origin header is accepted for no cookie setting.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_ORIGIN'] = 'http://www.example.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(None, req2)

    def test_bad_origin_header(self):
        """
        Test if a bad origin header is rejected for different domain.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_ORIGIN'] = 'http://www.evil.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(403, req2.status_code)

    @override_settings(PERMITTED_DOMAINS=['example.com'])
    def test_bad_origin_header_2(self):
        """
        Test if a bad origin header is rejected for subdomains.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_ORIGIN'] = 'http://www.example.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(403, req2.status_code)

    def test_bad_origin_header_3(self):
        """
        Test if a bad origin header is rejected with no cookie setting.
        """
        req = self._get_POST_request_with_headers()
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_ORIGIN'] = 'http://www.evil.com'
        req2 = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertEqual(403, req2.status_code)
