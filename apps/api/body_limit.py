"""Bound HTTP input before JSON parsing or any authenticated mutation."""
from starlette.responses import JSONResponse


class BodyLimit:
    def __init__(self, app, max_bytes=65536):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        lengths = [value for key, value in scope.get('headers', []) if key.lower() == b'content-length']
        if lengths and (len(lengths) != 1 or len(lengths[0]) > 20 or not lengths[0].isdigit()):
            return await JSONResponse({'detail': 'invalid content length'}, status_code=400)(scope, receive, send)
        if lengths and int(lengths[0]) > self.max_bytes:
            return await JSONResponse({'detail': 'request body too large'}, status_code=413)(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            size += len(chunk)
            if size > self.max_bytes:
                return await JSONResponse({'detail': 'request body too large'}, status_code=413)(scope, receive, send)
            chunks.append(chunk)
            if not message.get('more_body', False):
                break
        body, replayed = b''.join(chunks), False
        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return await receive()
        await self.app(scope, replay, send)
