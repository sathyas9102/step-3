from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.db import models
from django.contrib.auth.models import User


# Department model
class Department(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField()

    def __str__(self):
        return self.name

class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("The username must be set")
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, password, **extra_fields)
    
# Custom User model
class CustomUser(AbstractUser):
    is_admin = models.BooleanField(default=False)
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.SET_NULL)
    
    # Custom permissions
    can_edit = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    can_add_admin = models.BooleanField(default=False)
    
    def __str__(self):
        return self.username

# Daily Activity Report model
class DailyActivityReport(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True)
    task=models.CharField(max_length=255,default='No task assigned')
    news_count = models.IntegerField(default=0)
    insta_followers = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.task}"

