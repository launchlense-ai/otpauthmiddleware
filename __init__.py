import requests

class AuthMiddlewareService:
    def __init__(self):
        self.base_url = 'https://api.amw.launchlense.tech/api/v1/client/'
        self.access_key = None
        self.token = None

    def init_auth_middleware(self, access_key):
        self.access_key = access_key

    def post_request(self, endpoint, body, on_success, on_error, token=None):
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': self.access_key
        }
        if token:
            headers['Authorization'] = token

        try:
            response = requests.post(url, json=body, headers=headers)
            response.raise_for_status()
            on_success(response.json())
        except requests.exceptions.RequestException as error:
            on_error(f"Failed to send request: {error}")

    def get_ip_address(self):
        try:
            response = requests.get('https://api.ipify.org?format=json')
            response.raise_for_status()
            return response.json().get('ip')
        except requests.exceptions.RequestException as error:
            return None

    def login_with_email(self, email, password, on_success, on_error):
        ip_address = self.get_ip_address() or ''
        self.post_request(
            'login_with_email',
            {'email': email, 'password': password, 'ip': ip_address},
            on_success,
            on_error
        )

    def init_login(self, contact, otp_length, on_success, on_error, is_mfa=False, mfa_types=None, auth_type='otp'):
        ip_address = self.get_ip_address() or ''
        self.post_request(
            'init_login',
            {
                'contact': contact,
                'otp_length': otp_length,
                'type': auth_type,
                'ismfa': str(is_mfa).lower(),
                'mfaTypes': mfa_types or [],
                'ip': ip_address
            },
            on_success,
            on_error
        )

    def verify_auth(self, contact, password, on_success, on_error, is_biometric=False, biometrics_input=None):
        self.post_request(
            'verify_auth',
            {
                'contact': contact,
                'otp': password,
                'isbiometric': str(is_biometric).lower(),
                'biometrics_input': biometrics_input or {}
            },
            lambda response: self._handle_verify_auth_response(response, on_success, on_error),
            on_error
        )

    def _handle_verify_auth_response(self, response, on_success, on_error):
        if response.get('Status'):
            self.token = response.get('data')
            on_success(response)
        else:
            error_messages = {
                'USER_BANNED': 'You have been blocked from access',
                'INVALID_USER': 'Please enter correct contact number',
                'INVALID_CONTACT': 'Please enter correct contact number',
                'UNAUTHORIZED_USER': 'Resources you are trying to find are not found',
                'SERVER_ERROR': 'Something went wrong...'
            }
            error_msg = error_messages.get(response.get('message'), 'Unknown error')
            on_error(error_msg)

    def authorize_user(self, token, on_success, on_error):
        self.post_request('authorize_user', {}, on_success, on_error, token)
