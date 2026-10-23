"""Explicit certificate trust, independent of implicit proxy environment settings."""

import ssl

import certifi


def trust(bundle: str = "") -> ssl.SSLContext:
    # Extend the maintained bundle, rather than reintroducing retired roots from the OS store.
    context = ssl.create_default_context(cafile=certifi.where())
    if bundle:
        context.load_verify_locations(cafile=bundle)
    return context
