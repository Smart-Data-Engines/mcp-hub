"""Explicit certificate trust, independent of implicit proxy environment settings."""

import ssl


def trust(bundle: str = "") -> ssl.SSLContext | bool:
    if not bundle:
        return True
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=bundle)
    return context
