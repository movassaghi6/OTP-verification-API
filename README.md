# OTP Verification API

This project provides a Django-based API focused on OTP (One-Time Password) verification, enabling secure user registration and login using a phone number. The API implements security features such as failed attempt tracking, IP-based blocking, and OTP session management.

## Features
**User Registration**: Registers users with their phone number and sends an OTP for verification.

**OTP Verification**: Verifies the OTP to authenticate users.

**Login**: Allows users to log in using a phone number and OTP or a password.

**Failed Attempt Protection**: Blocks users after three failed login attempts for a period of time.

**Session-Based OTP Management**: Securely stores OTPs in user sessions for a limited time.

## Technologies
- Django
- Django Rest Framework (DRF)
- SQLite (or any Django-supported database)
- Python 3.x
## API Endpoints
**Register User**
- Sends an OTP to the user's phone number for registration.
```
Endpoint: /api/register/
Method: POST
Request Body:
{
   "phone_number": "1234567890"
}
Response:
{
   "message": "OTP sent to phone number"
}
```
**Verify OTP**
- Verifies the OTP sent to the user's phone number.
```
Endpoint: /api/verify-otp/
Method: POST
Request Body:
{
   "phone_number": "1234567890",
   "code": "123456"
}
Response:
{
   "message": "OTP verified successfully, proceed to login"
}
```
**Login User**
- Authenticates the user with OTP or password.
```
Endpoint: /api/login/
Method: POST
Request Body:
{
   "phone_number": "1234567890",
   "password": "123456"
}
Response:
{
   "message": "Login successful"
}
```
## Setup and Installation
- Clone the repository:
```  
git clone https://github.com/yourusername/otp-verification-api.git
cd otp-verification-api
```
- Create a virtual environment:
```
python3 -m venv env
source env/bin/activate
```
- Install dependencies:
```
pip install -r requirements.txt
```
- Apply migrations:
```
python manage.py makemigrations accounts
python manage.py migrate
``` 
- Run the server:
```
python manage.py runserver
```
- Access the API:
The API will be available at http://127.0.0.1:8000/api/.

## Security Features
**IP-Based Blocking**: Users are blocked for one hour after three consecutive failed login attempts, based on their IP address.

**Session-Based OTP Storage**: OTPs are securely stored in user sessions for temporary access, ensuring sensitive data is protected.
**Postman Collection**:
A Postman collection is available for testing the API:
## Future Enhancements
Implement email-based OTP verification.
Introduce rate limiting for enhanced security.
Add third-party SMS integration for OTP delivery.
