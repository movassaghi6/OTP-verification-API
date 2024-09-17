from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from datetime import timedelta


# Custom user manager to handle user creation logic
class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('The Phone Number must be set!')
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


# Custom user model
class User(AbstractBaseUser):
    """
    Custom user model that extends Django's AbstractBaseUser.
    It uses phone_number as the unique identifier for authentication
    instead of the default username.
    """

    phone_number = models.CharField(max_length=15, unique=True)
    email = models.EmailField(max_length=254, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    # Associate the custom manager with the User model
    objects = UserManager()

    USERNAME_FIELD = 'phone_number'

    def __str__(self):
        """
        String representation of the user, returning the phone number.
        """
        return self.phone_number
    

# OTP model for storing One-Time Passwords
class OTP(models.Model):
    """
    Model for storing One-Time Passwords (OTPs) associated with a phone number.
    Each OTP is valid for a certain period and can be used for authentication.
    """

    phone_number = models.CharField(max_length=15)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.phone_number} - {self.code}"


# Model to track failed login attempts
class FailedAttempt(models.Model):
    """
    Model to track failed login attempts based on phone number and IP address.
    If a user exceeds a certain number of failed attempts, they may be temporarily blocked.
    """

    phone_number = models.CharField(max_length=15)
    ip_address = models.GenericIPAddressField()
    attempts = models.PositiveIntegerField(default=0)
    last_attempt_time = models.DateTimeField(auto_now=True)

    def is_blocked(self):
        """
        Check if the user is blocked due to too many failed attempts.
        A user is blocked if they have made 3 or more attempts in the last hour.

        Returns:
            bool: True if the user is blocked, False otherwise.
        """

        return self.attempts >= 3 and (timezone.now() - self.last_attempt_time).total_seconds() < 3600

    def increment_attempts(self):
        """
        Increment the number of failed login attempts for a user and update the timestamp.
        """
        
        self.attempts += 1
        self.last_attempt_time = timezone.now()
        self.save()