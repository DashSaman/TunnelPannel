"""Reject oversized input before invoking code that changes account or billing state."""
import asyncio

import pytest

pytestmark = pytest.mark.unit_portable


def test_chunked_oversize_aborts_before_handler_and_does_not_consume_tail():
    from apps.api.body_limit import BodyLimit
    called, sent, chunks = [], [], []
    async def application(scope, receive, send):
        called.append(True)
    messages = iter([
        {'type': 'http.request', 'body': b'x'*40000, 'more_body': True},
        {'type': 'http.request', 'body': b'y'*40000, 'more_body': True},
    ])
    async def receive():
        item = next(messages)
        chunks.append(True)
        return item
    async def send(item):
        sent.append(item)
    asyncio.run(BodyLimit(application, max_bytes=65536)({'type':'http','headers':[]}, receive, send))
    assert not called
    assert len(chunks) == 2
    assert sent[0]['status'] == 413


def test_valid_body_is_replayed_exactly_once_and_large_declared_length_is_rejected():
    from apps.api.body_limit import BodyLimit
    bodies, sent = [], []
    async def application(scope, receive, send):
        message = await receive()
        bodies.append(message['body'])
        assert message['more_body'] is False
    async def receive():
        return {'type':'http.request','body':b'{"plan":"starter"}','more_body':False}
    async def send(item):
        sent.append(item)
    middleware = BodyLimit(application, max_bytes=65536)
    asyncio.run(middleware({'type':'http','headers':[]}, receive, send))
    assert bodies == [b'{"plan":"starter"}']
    async def should_not_receive():
        raise AssertionError('declared oversized body must be rejected before reading it')
    asyncio.run(middleware({'type':'http','headers':[(b'content-length',b'65537')]}, should_not_receive, send))
    assert len(bodies) == 1 and sent[0]['status'] == 413
    sent.clear()
    asyncio.run(middleware({'type':'http','headers':[(b'content-length',b'9'*5000)]}, should_not_receive, send))
    assert sent[0]['status'] == 400
