# AuthMiddlewareService

`AuthMiddlewareService` is a Python package for handling authentication middleware. This package provides methods to initialize authentication, login with email, verify authentication, and authorize a user. The package uses the `requests` library for making HTTP requests.

## Installation

To install the package, use pip:

```bash
pip install authmiddleware
```
## Aquire Access token
1. Sign Up with (https://portal.amw.launchlense.tech)
2. Create a new project
3. Get the access token and store it someplace safe

## Usage
Importing the Package
First, import the AuthMiddlewareService class:

from authmiddleware import AuthMiddlewareService

## Initializing the Service

Before using any methods, initialize the service with your access key:

auth = AuthMiddlewareService()
auth.init_auth_middleware('your-access-key-here')

## Login with Email

Use the login_with_email method to login with an email and password:

auth.login_with_email(
    'user@example.com',
    'password123',
    lambda data: print('Login successful:', data),
    lambda error: print('Login failed:', error)
)

## Initialize Login
Use the init_login method to initiate login with an OTP:

auth.init_login(
    'user@example.com',
    6,  # OTP length
    lambda data: print('Login initialized:', data),
    lambda error: print('Login initialization failed:', error)
)


## Verify Authentication
Use the verify_auth method to verify authentication with the received OTP:

auth.verify_auth(
    'user@example.com',
    'otp123456',
    lambda data: print('Verification successful:', data),
    lambda error: print('Verification failed:', error)
)

## Authorize User

Use the authorize_user method to authorize a user with a token:

auth.authorize_user(
    'user-token-here',
    lambda data: print('User authorized:', data),
    lambda error: print('Authorization failed:', error)
)

## Example

from authmiddleware import AuthMiddlewareService

def main():
    auth = AuthMiddlewareService()
    auth.init_auth_middleware('your-access-key-here')

    # Login with email
    auth.login_with_email(
        'user@example.com',
        'password123',
        lambda data: print('Login successful:', data),
        lambda error: print('Login failed:', error)
    )

    # Initialize login
    auth.init_login(
        'user@example.com',
        6,  # OTP length
        lambda data: print('Login initialized:', data),
        lambda error: print('Login initialization failed:', error)
    )

    # Verify authentication
    auth.verify_auth(
        'user@example.com',
        'otp123456',
        lambda data: print('Verification successful:', data),
        lambda error: print('Verification failed:', error)
    )

    # Authorize user
    auth.authorize_user(
        'user-token-here',
        lambda data: print('User authorized:', data),
        lambda error: print('Authorization failed:', error)
    )

if __name__ == '__main__':
    main()
