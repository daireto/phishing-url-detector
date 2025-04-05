from starlette.testclient import TestClient


class TestUserRouter:

    def test_predict(self, test_client: TestClient):
        url = 'https://www.google.com/search?q=python'
        response = test_client.post('/predict', json={'url': url})
        assert response.status_code == 200
        result = response.json()
        assert result['url'] == url
        assert result['phishing'] is False
        assert result['features']['url_length'] == 38

        phishing_url = 'http://google.com-redirect@valimail.com'
        response = test_client.post('/predict', json={'url': phishing_url})
        assert response.status_code == 200
        result = response.json()
        assert result['url'] == phishing_url
        assert result['phishing'] is True
        assert result['features']['url_length'] == 39
