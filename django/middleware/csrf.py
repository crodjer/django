"""
Cross Site Request Forgery Middleware.

This module provides a middleware that implements protection
against request forgeries from other sites.
"""

from django.conf import settings
from django.core.urlresolvers import get_callable
from django.utils.http import domain_permitted
from django.utils.log import getLogger

logger = getLogger('django.request')

REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - %s is not permitted."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."
REASON_BAD_ORIGIN = "Origin checking failed - %s is not permitted."

def _get_failure_view():
    """
    Returns the view to be used for CSRF rejections
    """
    return get_callable(settings.CSRF_FAILURE_VIEW)

def get_token(request):
    """
    Returns the the CSRF token required for a POST form. The token is an
    alphanumeric value.

    A side effect of calling this function is to make the the csrf_protect
    decorator and the CsrfViewMiddleware add a CSRF cookie and a 'Vary: Cookie'
    header to the outgoing response.  For this reason, you may need to use this
    function lazily, as is done by the csrf context processor.
    """

    return ""


class CsrfViewMiddleware(object):
    """
    Middleware that requires a present and correct csrfmiddlewaretoken
    for POST requests that have a CSRF cookie, and sets an outgoing
    CSRF cookie.

    This middleware should be used in conjunction with the csrf_token template
    tag.
    """
    # The _accept and _reject methods currently only exist for the sake of the
    # requires_csrf_token decorator.
    def _accept(self, request):
        # Avoid checking the request twice by adding a custom attribute to
        # request.  This will be relevant when both decorator and middleware
        # are used.
        request.csrf_processing_done = True
        return None

    def _reject(self, request, reason):
        return _get_failure_view()(request, reason=reason)

    def process_view(self, request, callback, callback_args, callback_kwargs):

        if getattr(request, 'csrf_processing_done', False):
            return None

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

            # Note that host includes the port.
            host = request.META.get('HTTP_HOST', '')
            origin = request.META.get('HTTP_ORIGIN')
            permitted_domains = getattr(settings, 'PERMITTED_DOMAINS', [host])

            # If origin header exists, use it to check for csrf attacks.
            # Origin header is being compared to None here as we need to reject
            # requests with origin header as '' too, which otherwise is treated
            # as null.
            if origin is not None:
                if not domain_permitted(origin, permitted_domains):
                    reason = REASON_BAD_ORIGIN % (origin)
                    logger.warning('Forbidden (%s): %s',
                                   reason, request.path,
                        extra={
                            'status_code': 403,
                            'request': request,
                        }
                    )

                    return self._reject(request, reason)

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
            referer = request.META.get('HTTP_REFERER')
            if referer is None:
                logger.warning('Forbidden (%s): %s',
                               REASON_NO_REFERER, request.path,
                    extra={
                        'status_code': 403,
                        'request': request,
                    }
                )

                return self._reject(request, REASON_NO_REFERER)

            if not domain_permitted(referer, permitted_domains):
                reason = REASON_BAD_REFERER % (referer)
                logger.warning('Forbidden (%s): %s', reason, request.path,
                    extra={
                        'status_code': 403,
                        'request': request,
                    }
                )
                return self._reject(request, reason)

        return self._accept(request)

    def process_response(self, request, response):
        if getattr(response, 'csrf_processing_done', False):
            return response

        # If CSRF_COOKIE is unset, then CsrfViewMiddleware.process_view was
        # never called, probaby because a request middleware returned a response
        # (for example, contrib.auth redirecting to a login page).
        if request.META.get("CSRF_COOKIE") is None:
            return response

        if not request.META.get("CSRF_COOKIE_USED", False):
            return response

        response.csrf_processing_done = True
        return response
