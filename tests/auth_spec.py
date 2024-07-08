import pytest, requests, jwt, os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
JWT_SECRET = os.environ.get('JWT_SECRET')

@pytest.fixture
def mrman():
    return {
        "firstName": "Jack",
        "lastName": "Dundee",
        "email": "jack.dundee@hill.com",
        "password": "ifelldownahill",
        "phone": "080419"
    }

@pytest.fixture
def mrbeast():
    return {
        "firstName": "Jimmy",
        "lastName": "Beast",
        "email": "jimmy.beast@hill.com",
        "password": "iamrich",
        "phone": "20000000"
    }

@pytest.fixture
def mrswoman():
    return {
        "firstName": "Jill",
        "lastName": "Dundee",
        "email": "jill.dundee@hill.com",
        "password": "fetchapale",
        "phone": "080111"
    }

@pytest.fixture
def boy():
    return {
        "firstName": "Jude",
        "lastName": "Dundee",
        "email": "jude.dundee@hill.com",
        "password": "itoofelldownahill",
        "phone": "01010101"
    }

@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_correct_token_generation(mrbeast):
    response = requests.post(f"{BASE_URL}/auth/register", json=mrbeast)
    data = response.json()
    
    assert response.status_code == 201
    assert "accessToken" in data['data']

    token = data['data']['accessToken']
    decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

    assert decoded_token['id'] == data['data']['user']['userId']
    assert datetime.utcfromtimestamp(decoded_token['exp']) < (datetime.now() + timedelta(minutes=16))

def test_organisation_access_control(mrman, mrswoman):
    response1 = requests.post(f"{BASE_URL}/auth/register", json=mrman)
    data1 = response1.json()
    token1 = data1['data']['accessToken']
    
    response2 = requests.post(f"{BASE_URL}/auth/register", json=mrswoman)
    data2 = response2.json()
    token2 = data2['data']['accessToken']
    
    org_payload = {
        "name": "Jack's seconnd Org",
        "description": "John's Description"
    }
    headers1 = {"Authorization": f"Bearer {token1}"}
    response = requests.post(f"{BASE_URL}/api/organisations", json=org_payload, headers=headers1)
    data = response.json()
    
    assert response.status_code == 200
    org_id = data['data']['orgId']
    
    # Jill tries to access Jack's organisation
    headers2 = {"Authorization": f"Bearer {token2}"}
    response = requests.get(f"{BASE_URL}/api/organisations/{org_id}", headers=headers2)
    
    assert response.status_code == 403
    assert response.json()['message'] == "user does not have access to this resource"

def test_register_endpoint(boy):
    response = requests.post(f"{BASE_URL}/auth/register", json=boy)
    data = response.json()
    
    assert response.status_code == 201
    assert data['status'] == "success"
    assert data['message'] == "Registration successful"
    assert "accessToken" in data['data']
    assert data['data']['user']['firstName'] == boy['firstName']
    assert data['data']['user']['lastName'] == boy['lastName']
    assert data['data']['user']['email'] == boy['email']
    
    # Check if a default organization is created
    token = data['data']['accessToken']
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/organisations", headers=headers)
    data = response.json()
    
    assert response.status_code == 200
    assert len(data['data']['organisations']) == 1
    assert data['data']['organisations'][0]['name'] == f"{boy['firstName']}'s Organisation"

def test_register_success():
    payload = {
        "firstName": "Toyin",
        "lastName": "Tomato",
        "email": "toyin.tomato@alata.com",
        "password": "my_password123",
        "phone": "1270015000"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 201
    assert data['status'] == "success"
    assert data['message'] == "Registration successful"
    assert "accessToken" in data['data']
    assert data['data']['user']['firstName'] == payload['firstName']
    assert data['data']['user']['lastName'] == payload['lastName']
    assert data['data']['user']['email'] == payload['email']

def test_register_with_missing_fields():
    # Missing firstName
    payload = {
        "lastName": "Doe",
        "email": "john.dodo@plantain.com",
        "password": "passss",
        "phone": "123444"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 422

    # Missing lastName
    payload = {
        "firstName": "Mary",
        "email": "mary.jane@hill.com",
        "password": "password123",
        "phone": "1234567890"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 422

    # Missing email
    payload = {
        "firstName": "Mark",
        "lastName": "Oga",
        "password": "password123",
        "phone": "1234567890"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 422

    # Missing password
    payload = {
        "firstName": "Naza",
        "lastName": "Doe",
        "email": "naza.doe@hng.com",
        "phone": "1270018000"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 422

def test_register_with_duplicate_email():
    payload = {
        "firstName": "Toyin",
        "lastName": "notTomato",
        "email": "toyin.tomato@alata.com",  # dupicate
        "password": "password123",
        "phone": "0987654321"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=payload)
    data = response.json()

    assert response.status_code == 422
    assert data['errors'][0]['field'] == "email"

def test_login_success():
    payload = {
        "email": "toyin.tomato@alata.com",
        "password": "my_password123"
    }
    response = requests.post(f"{BASE_URL}/auth/login", json=payload)
    data = response.json()

    assert response.status_code == 200
    assert data['status'] == "success"
    assert data['message'] == "Login successful"
    assert "accessToken" in data['data']
    assert data['data']['user']['email'] == payload['email']

def test_login_with_invalid_credentials():
    payload = {
        "email": "toyin.atarodo@alata.com", # this is invalid
        "password": "my_password123"
    }
    response = requests.post(f"{BASE_URL}/auth/login", json=payload)
    data = response.json()

    assert response.status_code == 401
    assert data['message'] == "Authentication failed"

    payload = {
        "email": "toyin.tomato@alata.com",
        "password": "mypassword123" # this is invalid
    }
    response = requests.post(f"{BASE_URL}/auth/login", json=payload)
    data = response.json()

    assert response.status_code == 401
    assert data['message'] == "Authentication failed"

if __name__ == "__main__":
    pytest.main()