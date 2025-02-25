# Intigriti 0125 xss challenge writeup

## Overview
It's a simple page that renders a text you give in the query param `text`
## Code review
1. XSS check: checks only if `>` or `<` is present in the url's query params or hash

```js
function XSS() {
	return decodeURIComponent(window.location.search).includes('<') || decodeURIComponent(window.location.search).includes('>') || decodeURIComponent(window.location.hash).includes('<') || decodeURIComponent(window.location.hash).includes('>')
}
```

2. Custom query param value retrieval: 

```js
function getParameterByName(name) {
	var url = window.location.href;
	name = name.replace(/[\[\]]/g, "\\$&");
	var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)");
	results = regex.exec(url);
	if (!results) return null;
	if (!results[2]) return '';
	return decodeURIComponent(results[2].replace(/\+/g, " "));
}
```

Surprisingly the `text` param's value is retrieved using a custom function that uses regexes to extract the value.

```javascript
var regex = new RegExp("[?&]text(=([^&#]*)|&|#|$)");
results = regex.exec(url);
```
This regex extracts the value after `?text=` or `&text=` from anywhere in the url -> so what if I could insert a payload in a place that is not the query params or the hash?

3. Text rendering: if no xss is detected, the text retrieved by `getParameterByName` gets inserted in the page via `innerHTML`

```js
function checkQueryParam() {
	const text = getParameterByName('text');
	if (text && XSS() === false) {
		const modal = document.getElementById('modal');
		const modalText = document.getElementById('modalText');
		modalText.innerHTML = `Welcome, ${text}!`;
		textForm.remove()
		modal.style.display = 'flex';
	}
}
```

## Exploitation

The first ideas that came into my mind were:
- include the payload in the url credentials
	- this doesn't work because `window.location.href` doesn't include credentials
- include the payload in the path

The latter is the correct approach, I just need to ensure that the browser does not normalize the path (eg: `/challenge/&text=xx/..` -> `/challenge`)

After a few minutes of testing I discovered that browsers generally do not normalize paths containing url-encoded separators like %2F, treating them as literal components rather than delimiters. For example this doesn't get normalized `/challenge/&text=xx%2f..`

Solution:
`https://challenge-0125.intigriti.io/challenge/&text=%3Cimg%20src=x%20onerror=alert(document.domain)%3E%2f..`