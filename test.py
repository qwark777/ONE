
VPS_IP = ('localhost')
PORT = 8001

import requests

def fetch_data(login, passs):
    url = f'http://{VPS_IP}:{PORT}/token'
    params = {
        'username': login,
        'password': passs,
        'grant_type': 'password'  # ОБЯЗАТЕЛЬНО для OAuth2PasswordRequestForm
    }

    try:
        response = requests.post(url, data=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Connection error: {e}")
        return None



# Пример использования
data = fetch_data('admin', '12345678')
print(data)