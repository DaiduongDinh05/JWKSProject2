"""All required imports for python code to function"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import datetime
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from database import get_db_connection

hostName = "localhost"
serverPort = 8080
#Generates a non-expired and expired key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
#Loads the keys into readable format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()
#Generates a non-expired and expired payload, converting exp into int format for sqlite
good_token_payload = {
    "user": "username",
    "exp": int(datetime.datetime.utcnow().timestamp()) + 50000
}
expired_token_payload = {
    "user": "username",
    "exp": int(datetime.datetime.utcnow().timestamp()) - 50000
}
#Inserts the non-expired and expired key on startup
connection = get_db_connection()
cursor = connection.cursor()
cursor.execute("INSERT INTO keys (key,exp) VALUES (?, ?)", (pem, good_token_payload["exp"]))
cursor.execute("INSERT INTO keys (key,exp) VALUES (?, ?)", (expired_pem, expired_token_payload["exp"]))
connection.commit()
connection.close()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    """Handles the web server logic, overloading BaseHTTPRequestHandler"""
    def do_PUT(self):
        """PUT logic, not handled, send 405"""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """PATCH logic, not handled, send 405"""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Delete logic, not handled, send 405"""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """HEAD logic, not handled, send 405"""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        """POST logic, generates a valid or expired key and stores it in the DB"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            #Generate a key on a POST request on /auth
            generated_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            #Serialize it into a readable format
            generated_pem = generated_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": int(datetime.datetime.utcnow().timestamp()) + 50000
            }
            #If a expired param exists, change the header and token payload
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = int(datetime.datetime.utcnow().timestamp()) - 50000
            connection = get_db_connection()
            cursor = connection.cursor()
            #Insert the private key into the DB
            cursor.execute("INSERT INTO keys (key,exp) VALUES (?, ?)", (generated_pem, token_payload["exp"]))
            connection.commit()
            connection.close()
            encoded_jwt = jwt.encode(token_payload, generated_pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        """GET logic, returns all valid keys"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            connection = get_db_connection()
            cursor = connection.cursor()
            #Select all private keys
            current_keys = cursor.execute("SELECT key FROM keys")
            current_keys = current_keys.fetchall()
            connection.close()
            key_list = []
            for key_tuple in current_keys: #Loops through each key
                key = key_tuple[0] #Obtains the key, each object stored as tuple
                #Since private key is known, seralize the key into a known format
                user_priv_key = serialization.load_pem_private_key(key,password=None,backend=default_backend())
                user_pub_key = user_priv_key.private_numbers() #Public numbers can be obtained from private key
                #Appends each serialized key to key_list
                key_list.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(user_pub_key.public_numbers.n),
                    "e": int_to_base64(user_pub_key.public_numbers.e),
                })
            keys_response = {"keys": key_list}
            self.wfile.write(bytes(json.dumps(keys_response), "utf-8")) #All keys are written to client as one JSON response
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
