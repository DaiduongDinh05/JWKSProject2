import pytest
import requests
import threading
import time
from http.server import HTTPServer
from main import MyServer, hostName, serverPort

@pytest.fixture(scope="module")
def test_server():
    """Fixture to start and stop the HTTP server in a separate thread."""
    httpd = HTTPServer((hostName, serverPort), MyServer)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    # Give the server a moment to start
    time.sleep(0.5)
    yield
    httpd.shutdown()
    thread.join()

def test_auth_endpoint_returns_200(test_server):
    """Test that /auth returns a 200 status code and a JWT."""
    url = f"http://{hostName}:{serverPort}/auth"
    response = requests.post(url)
    assert response.status_code == 200
    # Optionally test the response body is a JWT token
    assert "." in response.text  # Quick check for JWT format

def test_auth_endpoint_expired_key(test_server):
    """Test that /auth?expired returns a 200 but with an expired token."""
    url = f"http://{hostName}:{serverPort}/auth?expired=true"
    response = requests.post(url)
    assert response.status_code == 200
    # Additional checks for the token payload or 'kid' in headers

def test_well_known_endpoint(test_server):
    """Test that /.well-known/jwks.json returns 200 and valid JSON."""
    url = f"http://{hostName}:{serverPort}/.well-known/jwks.json"
    response = requests.get(url)
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    # Additional checks that each key has 'alg', 'kty', 'use', 'kid', 'n', 'e'

def test_put_endpoint(test_server):
    """Tests that put returns 405"""
    url = f"http://{hostName}:{serverPort}/"
    response = requests.put(url)
    assert response.status_code == 405

def test_patch_endpoint(test_server):
    """Test that patch returns 405"""
    url = f"http://{hostName}:{serverPort}/"
    response = requests.patch(url)
    assert response.status_code == 405

def test_delete_endpoint(test_server):
    """Test that delete returns 405"""
    url = f"http://{hostName}:{serverPort}/"
    response = requests.delete(url)
    assert response.status_code == 405
    
def test_head_endpoint(test_server):
    """Test that head returns 405"""
    url = f"http://{hostName}:{serverPort}/"
    response = requests.head(url)
    assert response.status_code == 405