import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import datetime
import uuid
import json
import jwt
import logging
import concurrent.futures
import ConfigParser
import os

# Define logging. Used below line for printing output to console for cylance file
logger = logging.getLogger(__name__)

MAX_THREADS = 14  # Get max number of threads for multi-threading
api = 'https://protectapi.cylance.com/'  # Base Cylance API
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Cylance_creds'))
cylance_client_id = Config.get('Settings', 'Cylance_Application_ID')
cylance_secret = Config.get('Settings', 'Cylance_Secret')
cylance_tenant_id = Config.get('Settings', 'Cylance_Tenant_ID')


# Generate session with max of 3 retries and interval of 60 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=30)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Create session token
'''
Output: Return session token
'''
def session_creation():
    logger.info('Creation session token to be used in Cylance')

    # Use epoch time in seconds
    session_time_start = int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds())
    session_time_end = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=30) - datetime.datetime(1970, 1, 1)).total_seconds())

    random_token = str(uuid.uuid4())
    auth_api = '%sauth/v2/token' % api
    data = {
        "exp": session_time_end,
        "iat": session_time_start,
        "iss": "http://cylance.com",
        "sub": cylance_client_id,
        "tid": cylance_tenant_id,
        "jti": random_token
    }

    payload = {'auth_token': jwt.encode(data, cylance_secret, algorithm='HS256').decode('utf8').replace("'", '"')}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    session = session_generator()
    resp = session.post(auth_api, headers=headers, data=json.dumps(payload))
    if resp.ok:
        response = resp.json()
        if 'access_token' in response:
            return response['access_token']
    else:
        logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
        return None


# Class to device information
class Detection:
    def __init__(self):
        self.name = None
        self.devices = []
        self.action = []
        self.creation = None
        self.hash = None
        self.severity = None
        self.score = 1
        self.path = []
        self.link = None

    def fill_threat_details(self, access_token):
        page = 1
        session = session_generator()
        while True:
            device_api = '%sthreats/v2/%s/devices?page=%d&page_size=200' % (api, self.hash, page)
            headers = {'Authorization': 'Bearer %s' % access_token, "Content-Type": "application/json; charset=utf-8"}
            resp = session.get(device_api, headers=headers)
            if resp.ok:
                response = resp.json()
                total_pages = response['total_pages']
                if response['page_items']:
                    for device in response['page_items']:
                        threat_found = datetime.datetime.strptime(device['date_found'].split('.')[0],
                                                                  '%Y-%m-%dT%H:%M:%S')
                        if threat_found == self.creation:
                            self.devices.append(device['name'])
                            self.action.append(device['file_status'])
                            self.path.append(device['file_path'])
                page = page + 1
                if page > total_pages:
                    break
            elif resp.status_code == 401:
                logger.warning('Cylance session token expired. Recreating cylance session.')
                access_token = session_creation()
            else:
                logger.critical('Unable to update threat %s' % self.name)
                logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
                break

        if self.devices:
            self.devices = list(set(self.devices))
        if self.action:
            self.action = list(set(self.action))
        if self.path:
            self.path = list(set(self.path))


def get_threat_hashes(access_token, duration):
    threats = []
    page = 1
    logger.info("Fetching threats seen in the past %d seconds" % duration)
    session = session_generator()
    while True:
        threat_api = '%sthreats/v2?page=%d&page_size=200' % (api, page)
        headers = {'Authorization': 'Bearer %s' % access_token, "Content-Type": "application/json; charset=utf-8"}
        resp = session.get(threat_api, headers=headers)
        if resp.ok:
            response = resp.json()
            total_pages = response['total_pages']
            if response['page_items']:
                for detection in response['page_items']:
                    detectionobj = Detection()
                    detectionobj.name = detection['name']
                    detectionobj.hash = detection['sha256']
                    detectionobj.score = detection['cylance_score']
                    detectionobj.link = 'https://protect.cylance.com/Threats/ThreatDetails/%s' % detectionobj.hash
                    detectionobj.creation = datetime.datetime.strptime(detection['last_found'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    if (datetime.datetime.utcnow() - detectionobj.creation).days < 1 and (datetime.datetime.utcnow() - detectionobj.creation).seconds <= duration and not detection['safelisted']:
                        if detectionobj.score is not None and detectionobj.score < 0:
                            threats.append(detectionobj)
                        elif detectionobj.score is None:
                            detectionobj.score = 2
                            threats.append(detectionobj)

            page = page + 1
            if page > total_pages:
                break
        elif resp.status_code == 401:
            logger.warning('Cylance session token expired. Recreating cylance session.')
            access_token = session_creation()
        else:
            logger.critical('Unable to threats from Cylance.')
            logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
            break
    return access_token, threats


def fetch_detections(duration):
    access_token = session_creation()
    if access_token is None:
        return None

    token, threats = get_threat_hashes(access_token, duration)
    if token != access_token:
        access_token = token

    if threats:
        logger.info("Fetching threat associated with device from Cylance")
        with concurrent.futures.ThreadPoolExecutor(max_workers = MAX_THREADS) as executor:
            for threat in threats:
                executor.submit(threat.fill_threat_details, access_token)
    else:
        threats = []

    return threats
