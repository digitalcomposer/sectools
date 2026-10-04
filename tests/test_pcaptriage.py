from __future__ import annotations

import base64

from sectools.tools import pcaptriage


def test_decode_basic_auth():
    token = base64.b64encode(b"alice:s3cret").decode()
    parsed = pcaptriage.decode_basic_auth(f"Basic {token}")
    assert parsed == {"scheme": "http-basic", "username": "alice", "password": "s3cret"}


def test_decode_basic_auth_rejects_garbage():
    assert pcaptriage.decode_basic_auth("Basic not-base64!!") is None
    token = base64.b64encode(b"no-colon-here").decode()
    assert pcaptriage.decode_basic_auth(f"Basic {token}") is None
