import unittest
import pro

class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        # Set up a session to use in tests
        self.session = requests.Session()
        self.base_url = "http://localhost:8080"

    def test_get_auth_endpoint(self):
        response = self.session.get(f"{self.base_url}/auth")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)  # Check if the response is not empty

    def test_get_jwks_endpoint(self):
        response = self.session.get(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)  # Check if the response is not empty

    def test_put_jwks_endpoint(self):
        response = self.session.put(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)  # Expecting a Method Not Allowed response

    def test_patch_jwks_endpoint(self):
        response = self.session.patch(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)  # Expecting a Method Not Allowed response

    def test_delete_jwks_endpoint(self):
        response = self.session.delete(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)  # Expecting a Method Not Allowed response

    def test_post_jwks_endpoint(self):
        response = self.session.post(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)  # Expecting a Method Not Allowed response

if __name__ == "__main__":
    unittest.main()

