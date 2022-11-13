from __future__ import annotations
import pytest
import requests
from time import sleep
from typing import Dict, Literal, Union
from multiprocessing import Process
from py4web.core import bottle, wsgi
from py4web import core
from ..common import db, accessManager
import uuid
from dataclasses import dataclass
import os

PENDING_REGISTRATION_TOKEN = 'pending-registration'
BASE_APPLICATION_URL = 'http://127.0.0.1:8000'

class ApplicationTesting:

    def __init__(self):
        os.environ["PY4WEB_APPS_FOLDER"] = "/apps"
        self.server = Process(target=ApplicationTesting.run_application)        

    def start_server(self):
        self.server.start()
        sleep(3)

    def stop_server(self):
        self.server.terminate() 

    @staticmethod
    def run_application():
        bottle.run(host='0.0.0.0', port=8000)   
        

@pytest.fixture(scope='module')
def initialize_application():
    application = ApplicationTesting()
    application.start_server()
    yield application
    application.stop_server()


def send_request(url: str, 
                base_url: str = BASE_APPLICATION_URL,
                method: Literal['GET', 'POST', 'PUT', 'DELETE'] = 'GET',
                data: Union[dict, None] = None,
                session: Union[requests.Session, None] = None,
                headers: Union[Dict, None] = None) -> requests.Response:
    
    url = f"{base_url.strip('/')}/{url.strip('/')}"
    
    req = session if session else requests

    if base_url == BASE_APPLICATION_URL:
        # Ensure any pending changes are committed before sending the request
        # otherwise the SQLite DB will be locked.
        db.commit() 

    if method == 'GET':
        assert data is None
        return req.get(url=url, headers=headers)

    elif method == 'POST':
        assert data is not None
        return req.post(url=url, data=data, headers=headers)

@dataclass
class RequestTest:
    __test__ = False # So pytest doesn't attempt to collect it as a Test Class.
    _ajax_header = 'application/json'

    request_url: str
    response_url: Union[str, None] = None    
    user: Union[TestUser, None] = None
    expected_status: int = 200
    expected_body: Union[bytes, None] = None
    data: Union[dict, None] = None
    method: Literal['GET', 'POST'] = 'GET'
    ajax_request: bool = True

    def __post_init__(self):
        assert isinstance(self.request_url, str)
        assert isinstance(self.response_url, str) or (self.response_url is None)
        assert isinstance(self.user, TestUser) or (self.user is None)
        assert isinstance(self.expected_status, int)
        assert isinstance(self.expected_body, bytes) or (self.expected_body is None)
        assert isinstance(self.data, dict) or (self.data is None)
        assert isinstance(self.method, str) and self.method in ('GET', 'POST')
        assert isinstance(self.ajax_request, bool)

    def send(self, session = None):
        
        self.response = send_request(self.request_url, 
                                     data = self.data,
                                     method = self.method, 
                                     session = session if session else None,
                                     headers = {"accept": self._ajax_header} if self.ajax_request else None)
        return self.response


class TestUser:

    __test__ = False # So pytest doesn't attempt to collect it as a Test Class.
    table = accessManager.auth_user

    def __init__(self,
                 first_name: str,
                 last_name: str) -> None:
        
        self.first_name = first_name
        self.last_name = last_name
        
        generated_id = str(uuid.uuid4())            

        self.username = generated_id
        self.email = f'{generated_id}@email.com'
        self.password = generated_id
        self.user_id = None
        self.session = requests.Session()
        self.user_record = None
        
    def create(self):
        self.register_user().verify_email().login()

    def get_registration_details(self):
        return dict(username=self.username,
                    email=self.email,
                    password=self.password,
                    first_name=self.first_name,
                    last_name=self.last_name,)

    def get_login_details(self):
        return dict(email=self.email,
                    password=self.password,)
    
    def register_user(self) -> TestUser:
        res = send_request('auth/api/register', data=self.get_registration_details(), method='POST')
        assert res.status_code == 200
        content = res.json()
        self.user_id = content['id']
        return self

    def verify_email(self) -> TestUser:        
        self.user_record = db.auth_user[self.user_id]
        assert self.user_record.action_token.startswith(PENDING_REGISTRATION_TOKEN)
        verify_email_token = self.user_record.action_token[len(PENDING_REGISTRATION_TOKEN) + 1 : ]
        res = send_request(f'auth/api/verify_email?token={verify_email_token}')
        assert res.status_code == 200
        return self

    def login(self) -> TestUser:        
        res = send_request('auth/api/login', 
                           data=self.get_login_details(), 
                           method='POST',
                           session=self.session)

        assert res.status_code == 200
        return self

