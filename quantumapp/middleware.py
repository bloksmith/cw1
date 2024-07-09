# quantumapp/middleware.py

from urllib.parse import urlparse
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class CustomOriginMiddleware:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope):
        if isinstance(scope, dict) and 'headers' in scope:
            headers = dict(scope['headers'])
            origin = headers.get(b'origin', None)
            logger.debug(f"Received headers: {headers}")

            if origin:
                origin = origin.decode('utf-8')
                parsed_origin = urlparse(origin)
                logger.debug(f"Parsed origin: {parsed_origin.netloc}")
                if parsed_origin.netloc in settings.ALLOWED_HOSTS:
                    logger.debug(f"Origin {parsed_origin.netloc} is allowed.")
                    return self.inner(scope)
                else:
                    logger.warning(f"Origin {parsed_origin.netloc} is not in ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}")
            else:
                logger.warning("No origin header found.")

            logger.warning(f"Access denied due to invalid origin: {origin}")
            raise ValueError("Access denied")
        else:
            logger.debug("Non-ASGI request passed through middleware.")
            return self.inner(scope)
