import random
from rest_framework import status, views
from rest_framework.response import Response
from django.contrib.auth import authenticate, login
from .models import User, OTP, FailedAttempt

class BaseView(views.APIView):
    """
    Base class for handling common functionalities such as failed attempt checking and incrementing.
    """

    def check_failed_attempts(self, phone_number, ip_address):
        """
        Check if the user has too many failed login attempts.
        """

        failed_attempt = FailedAttempt.objects.filter(phone_number=phone_number, ip_address=ip_address).first()
        if failed_attempt and failed_attempt.is_blocked():
            print(f"User blocked due to too many failed attempts: {phone_number}, {ip_address}")
            return True, failed_attempt
        return False, failed_attempt

    def increment_failed_attempts(self, phone_number, ip_address):
        """
        Increment the count of failed login attempts for the specified phone number and IP address.
        """

        failed_attempt, created = FailedAttempt.objects.get_or_create(phone_number=phone_number, ip_address=ip_address)
        failed_attempt.increment_attempts()
        print(f"Failed attempts incremented: {failed_attempt.attempts} for {phone_number}, {ip_address}")


class RegisterView(BaseView):
    """
    View for handling user registration via phone number and OTP (One-Time Password).
    """

    def post(self, request):
        """
        Handle POST request for registering a user and sending an OTP.
        """

        phone_number = request.data.get('phone_number')
        if not phone_number:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(phone_number=phone_number).exists():
            return Response({'message': 'User already registered'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a 6-digit OTP code
        otp_code = str(random.randint(100000, 999999))
        OTP.objects.create(phone_number=phone_number, code=otp_code)

        # Store OTP code and phone number in session
        request.session['otp_code'] = otp_code
        request.session['phone_number'] = phone_number

        # Simulate sending the OTP via SMS (for example purposes, it's just printed)
        print(f"OTP Code: {otp_code}")
        return Response({'message': 'OTP sent to phone number'}, status=status.HTTP_200_OK)


class VerifyOTPView(BaseView):
    """
    View for handling OTP verification.
    """

    def post(self, request):
        phone_number = request.data.get('phone_number') or request.session.get('phone_number')
        code = request.data.get('code') or request.session.get('otp_code')
        ip_address = request.META.get('REMOTE_ADDR')

        if not phone_number:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if not code:
            return Response({'error': 'OTP code is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user is blocked due to too many failed attempts
        is_blocked, failed_attempt = self.check_failed_attempts(phone_number, ip_address)
        if is_blocked:
            return Response({"error": "Too many failed attempts. Please try again after 1 hour."}, status=status.HTTP_403_FORBIDDEN)

        # Verify OTP
        otp_instance = OTP.objects.filter(phone_number=phone_number, code=code).first()
        if not otp_instance:
            self.increment_failed_attempts(phone_number, ip_address)
            return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        # Create or get the user associated with the phone number
        user, created = User.objects.get_or_create(phone_number=phone_number)
        if created:
            user.email = request.data.get('email')
            user.first_name = request.data.get('first_name')
            user.last_name = request.data.get('last_name')
            user.set_password(code)
            user.save()

        # Store phone number and OTP code for later use in login
        request.session['phone_number'] = phone_number
        request.session['otp_code'] = code

        # Clear failed attempts if the user successfully verifies OTP
        if failed_attempt:
            failed_attempt.delete()

        return Response({'message': 'OTP verified successfully, proceed to login'}, status=status.HTTP_200_OK)


class LoginView(BaseView):
    """
    View for handling user login using phone number and OTP/password.
    """

    def post(self, request):
        phone_number = request.data.get('phone_number') or request.session.get('phone_number')
        password = request.data.get('password') or request.session.get('otp_code')
        ip_address = request.META.get('REMOTE_ADDR')

        if not phone_number:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if not password:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the user is blocked due to too many failed attempts
        is_blocked, failed_attempt = self.check_failed_attempts(phone_number, ip_address)
        if is_blocked:
            return Response({"error": "Too many failed attempts. Please try again after 1 hour."}, status=status.HTTP_403_FORBIDDEN)
       
        # Authenticate user
        user = authenticate(request, username=phone_number, password=password)
        if user is not None:
            login(request, user)
            
            # Clear failed attempts on successful login
            if failed_attempt:
                failed_attempt.delete()

            # Clear session data after successful login
            request.session.pop('otp_code', None)
            request.session.pop('phone_number', None)

            return Response({"message": "Login successful."}, status=status.HTTP_200_OK)

        # Increment failed attempts if authentication fails
        self.increment_failed_attempts(phone_number, ip_address)
        return Response({"error": "Invalid phone number or password."}, status=status.HTTP_401_UNAUTHORIZED)