from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple
import base64
import json
import jwt
import datetime
import sqlite3

# Function to convert an integer to Base64URL-encoded string
def int_to_base64(value):
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Function to serialize the private key to PKCS1 PEM format
def serialize_key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

# Function to deserialize the private key from PKCS1 PEM format
def deserialize_pem_to_key(pem_string):
    return serialization.load_pem_private_key(pem_string.encode('utf-8'), password=None)

# Function to get all valid keys from the DB
def get_all_valid_private_keys_with_kid() -> List[Tuple[int, RSAPrivateKey]]:
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
        cursor = conn.execute(query, (current_time,))
        key_data = cursor.fetchall()

    keys = [(data[0], deserialize_pem_to_key(data[1])) for data in key_data]
    return keys

# Function to get un/expired key from DB
def get_private_key_with_kid_from_db(expired=False):
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp {} ? ORDER BY exp {} LIMIT 1".format(
        '<' if expired else '>', 'DESC' if expired else 'ASC')

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
        cursor = conn.execute(query, (current_time,))
        key_data = cursor.fetchone()

    if key_data:
        return key_data[0], deserialize_pem_to_key(key_data[1])
    return None, None

# Create and initialize DB
conn = sqlite3.connect('totally_not_my_privateKeys.db')
conn.execute('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, '
             'key BLOB NOT NULL, exp INTEGER NOT NULL)')
conn.commit()

# Create and serialize keys
init_unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_unexpired_key_PEM = serialize_key_to_pem(init_unexpired_key)
init_expired_key_PEM = serialize_key_to_pem(init_expired_key)

now = int(datetime.datetime.utcnow().timestamp())
hour_from_now = now + 3600

# Insert the serialized keys into the DB
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (init_unexpired_key_PEM, hour_from_now))
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (init_expired_key_PEM, (now - 3600)))
conn.commit()

hostName = "localhost"
serverPort = 8080

# Configure web server requests/actions
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            kid, key = get_private_key_with_kid_from_db('expired' in params)

            if not key:
                self.send_response(500, "Unable to fetch private key")
                self.end_headers()
                return

            headers = {"kid": str(kid)}
            token_payload = {"user": "username", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            key_pem = serialize_key_to_pem(key)
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            valid_keys_with_kid = get_all_valid_private_keys_with_kid()
        jwks = {"keys": []}
        for kid, key in valid_keys_with_kid:
            private_numbers = key.private_numbers()
            jwks["keys"].append({
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(private_numbers.public_numbers.n),
                "e": int_to_base64(private_numbers.public_numbers.e)
            })

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json.dumps(jwks), "utf-8"))

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

