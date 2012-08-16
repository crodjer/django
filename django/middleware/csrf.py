"""
Cross Site Request Forgery Middleware.

This module provides a middleware that implements protection
against request forgeries from other sites.
"""
from __future__ import unicode_literals

import hashlib
import re
import random

from django.conf import settings
from django.core.urlresolvers import get_callable
from django.utils.cache import patch_vary_headers
from django.utils.encoding import force_text
from django.utils.http import same_origin
from django.utils.log import getLogger
from django.utils.crypto import constant_time_compare, get_random_string

logger = getLogger('django.request')

REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - %s does not match %s."
REASON_NO_CSRF_COOKIE = "CSRF cookie not set."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."

CSRF_KEY_LENGTH = 32

def _get_failure_view():
    """
    Returns the view to be used for CSRF rejections
    """
    return get_callable(settings.CSRF_FAILURE_VIEW)


def _get_new_csrf_key():
    return get_random_string(CSRF_KEY_LENGTH)


def get_token(request):
    """
    Returns the the CSRF token required for a POST form. The token is an
    alphanumeric value.

    A side effect of calling this function is to make the the csrf_protect
    decorator and the CsrfViewMiddleware add a CSRF cookie and a 'Vary: Cookie'
    header to the outgoing response.  For this reason, you may need to use this
    function lazily, as is done by the csrf context processor.
    """
    request.META["CSRF_COOKIE_USED"] = True
    return request.META.get("CSRF_COOKIE", None)


def _sanitize_token(token):
    # Allow only alphanum
    if len(token) > CSRF_KEY_LENGTH:
        return _get_new_csrf_key()
    token = re.sub('[^a-zA-Z0-9]+', '', force_text(token))
    if token == "":
        # In case the cookie has been truncated to nothing at some point.
        return _get_new_csrf_key()
    return token


class CsrfChecker(object):
    """
    A CSRF Checker.
    """

    def __init__(self, request, callback, callback_args, callback_kwargs):
        self.request = request
        self.callback = callback
        self.callback_args = callback_args
        self.callback_kwargs = callback_kwargs

    def _reject(self, request, reason):
        return _get_failure_view()(request, reason=reason)

    def process_response(self, request):
        return request


class TokenChecker(CsrfChecker):

    def __init__(self, *args, **kwargs):
        super(TokenChecker, self).__init__(*args, **kwargs)

        try:
            csrf_token = _sanitize_token(
                self.request.COOKIES[settings.CSRF_COOKIE_NAME])
            # Use same token next time
            self.request.META['CSRF_COOKIE'] = csrf_token
        except KeyError:
            csrf_token = None
            # Generate token and store it in the request, so it's
            # available to the view.
            self.request.META["CSRF_COOKIE"] = _get_new_csrf_key()

        self.token = csrf_token

    def check(self):

        if self.token is None:
            # No CSRF cookie. For POST requests, we insist on a CSRF cookie,
            # and in this way we can avoid all CSRF attacks, including login
            # CSRF.
            logger.warning('Forbidden (%s): %s',
                           REASON_NO_CSRF_COOKIE, self.request.path,
                extra={
                    'status_code': 403,
                    'request': self.request,
                }
            )
            return self._reject(self.request, REASON_NO_CSRF_COOKIE)

        # Check non-cookie token for match.
        request_csrf_token = ""
        if self.request.method == "POST":
            request_csrf_token = self.request.POST.get('csrfmiddlewaretoken', '')

        if request_csrf_token == "":
            # Fall back to X-CSRFToken, to make things easier for AJAX,
            # and possible for PUT/DELETE.
            request_csrf_token = self.request.META.get('HTTP_X_CSRFTOKEN', '')

        if not constant_time_compare(request_csrf_token, self.token):
            logger.warning('Forbidden (%s): %s',
                           REASON_BAD_TOKEN, self.request.path,
                extra={
                    'status_code': 403,
                    'request': self.request,
                }
            )
            return self._reject(self.request, REASON_BAD_TOKEN)

        return None

    def process_response(self, response):

        # If CSRF_COOKIE is unset, then CsrfViewMiddleware.process_view was
        # never called, probaby because a request middleware returned a response
        # (for example, contrib.auth redirecting to a login page).
        if self.request.META.get("CSRF_COOKIE") is None:
            return response

        if not self.request.META.get("CSRF_COOKIE_USED", False):
            return response

        # Set the CSRF cookie even if it's already set, so we renew
        # the expiry timer.
        response.set_cookie(settings.CSRF_COOKIE_NAME,
                            self.request.META["CSRF_COOKIE"],
                            max_age = 60 * 60 * 24 * 7 * 52,
                            domain=settings.CSRF_COOKIE_DOMAIN,
                            path=settings.CSRF_COOKIE_PATH,
                            secure=settings.CSRF_COOKIE_SECURE
                            )
        # Content varies with the CSRF cookie, so set the Vary header.
        patch_vary_headers(response, ('Cookie',))
        response.csrf_processing_done = True

        return response


class RefererChecker(CsrfChecker):
    def __init__(self, *args, **kwargs):
        super(RefererChecker, self).__init__(*args, **kwargs)

        # Suppose user visits http://example.com/
        # An active network attacker (man-in-the-middle, MITM) sends a
        # POST form that targets https://example.com/detonate-bomb/ and
        # submits it via JavaScript.
        #
        # The attacker will need to provide a CSRF cookie and token, but
        # that's no problem for a MITM and the session-independent
        # nonce we're using. So the MITM can circumvent the CSRF
        # protection. This is true for any HTTP connection, but anyone
        # using HTTPS expects better! For this reason, for
        # https://example.com/ we need additional protection that treats
        # http://example.com/ as completely untrusted. Under HTTPS,
        # Barth et al. found that the Referer header is missing for
        # same-domain requests in only about 0.2% of cases or less, so
        # we can use strict Referer checking.
        self.strict = self.request.is_secure()

    def check(self):
        referer = self.request.META.get('HTTP_REFERER')

        if referer is None:
            # Referer checker is lax if request is not secure.
            if self.strict:
                logger.warning('Forbidden (%s): %s',
                               REASON_NO_REFERER, self.request.path,
                    extra={
                        'status_code': 403,
                        'request': self.request,
                    }
                )
                return self._reject(self.request, REASON_NO_REFERER)
        else:
            # Note that request.get_host() includes the port.
            good_referer = 'https://%s/' % self.request.get_host()
            if not same_origin(referer, good_referer):
                reason = REASON_BAD_REFERER % (referer, good_referer)
                logger.warning('Forbidden (%s): %s', reason, self.request.path,
                    extra={
                        'status_code': 403,
                        'request': self.request,
                    }
                )
                return self._reject(self.request, reason)

        return None


class CsrfViewMiddleware(object):
    """
    Middleware that requires a present and correct csrfmiddlewaretoken
    for POST requests that have a CSRF cookie, and sets an outgoing
    CSRF cookie.

    This middleware should be used in conjunction with the csrf_token template
    tag.
    """

    def __init__(self, *args, **kwargs):
        self.checker_classes = [
            RefererChecker,
            TokenChecker
        ]
        self.checkers = []

    # The _accept and _reject methods currently only exist for the sake of the
    # requires_csrf_token decorator.
    def _accept(self, request):
        # Avoid checking the request twice by adding a custom attribute to
        # request.  This will be relevant when both decorator and middleware
        # are used.
        request.csrf_processing_done = True
        return None

    def process_view(self, request, callback, callback_args, callback_kwargs):

        if getattr(request, 'csrf_processing_done', False):
            return None

        for checker in self.checker_classes:
            self.checkers.append(checker(request, callback, callback_args, callback_kwargs))

        # Wait until request.META["CSRF_COOKIE"] has been manipulated before
        # bailing out, so that get_token still works
        if getattr(callback, 'csrf_exempt', False):
            return None

        # Assume that anything not defined as 'safe' by RC2616 needs protection
        if request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            if getattr(request, '_dont_enforce_csrf_checks', False):
                # Mechanism to turn off CSRF checks for test suite.
                # It comes after the creation of CSRF cookies, so that
                # everything else continues to work exactly the same
                # (e.g. cookies are sent, etc.), but before any
                # branches that call reject().
                return self._accept(request)

            for checker in self.checkers:
                result = checker.check()
                if result:
                    return result

        return self._accept(request)

    def process_response(self, request, response):
        if getattr(response, 'csrf_processing_done', False):
            return response

        for checker in self.checkers:
            response = checker.process_response(response)

        return response
