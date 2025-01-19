from datetime import datetime,date
from django.shortcuts import render, redirect
import openpyxl
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login
from .forms import  DailyActivityReportForm
from .models import DailyActivityReport, CustomUser , Department
from django.contrib.auth.decorators import login_required , user_passes_test
from  django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
import random
from django.conf import settings
from django.contrib.auth import get_user_model  
from django.core.exceptions import ObjectDoesNotExist



def home(request):
    return render(request, 'users/login.html')

def create_user(request):
    return render(request, 'users/create_user.html' )

# Login Page 
def custom_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
       
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            print(f"Authenticated user: {user.username}")
            auth_login(request, user)
            user_department = user.department.name if hasattr(user, 'department') else "General"

           
            if user.is_superuser:
                print("User is superuser (admin)")
                return redirect('users:admin_dashboard')  
            else:
                print("User is not admin")
                return redirect('users:daily_activity_{user_department.lower()}') 
        else:
            print("Authentication failed.")
            messages.error(request, "Invalid username or password!")
            return render(request, 'users/login.html')

    return render(request, 'users/login.html')

# Admin Dashboard (Add User/Admin page)
@login_required
def admin_dashboard(request):
    action = request.GET.get('action')
    departments = Department.objects.all()

    if request.method == 'POST':
        # Get the form data
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        department_name = request.POST.get('department')

        # Check if the department exists
        try:
            department = Department.objects.get(name=department_name)
        except Department.DoesNotExist:
            return render(request, 'users/admin_dashboard.html', {
                'action': action,
                'departments': departments,
                'error': f"Department {department_name} does not exist!"
            })

        # Check if the username already exists
        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'users/admin_dashboard.html', {
                'action': action,
                'departments': departments,
                'error': f"Username {username} already exists!"
            })

        # Create the user based on the action
        if action == 'add_user':
            user = CustomUser.objects.create_user(username=username, password=password)
            user.save()
            

        elif action == 'add_admin':
            user = CustomUser.objects.create_user(username=username, password=password)
            user.is_staff = True
            user.is_superuser = True
            user.save()

            permissions = request.POST.getlist('permissions')
            if 'can_edit' in permissions:
                user.can_edit = True
            if 'can_delete' in permissions:
                user.can_delete = True
            if 'can_add_admin' in permissions:
                user.can_add_admin = True
            user.save()

        # Redirect to the same page after the operation
        return redirect('users:admin_dashboard')

    return render(request, 'users/admin_dashboard.html', {
        'action': action,
        'departments': departments
    })
   
# User Daily Activity Page
@login_required
def daily_activity_department(request, department_name):
    user = request.user

    if user.department.name.lower() != department_name.lower():
        messages.error(request, "You don't have access to this department's directory.")
        return redirect('users:daily_activity')

    today = date.today()
    daily_reports = DailyActivityReport.objects.filter(user__department__name=department_name, date=today)

    if request.method == 'POST':
        form = DailyActivityReportForm(request.POST)

        if form.is_valid():
            activity_report = form.save(commit=False)
            activity_report.user = user
            activity_report.save()
            messages.success(request, f"Your daily activity report for {department_name} has been updated.")
            return redirect(f'users:daily_activity_{department_name.lower()}')
    else:
        form = DailyActivityReportForm()

    return render(request, f'users/daily_activity_{department_name.lower()}.html', {
        'form': form,
        'daily_reports': daily_reports,
    })


@login_required
def export_excel_department(request, department_name):
    user = request.user

    if user.department.name.lower() != department_name.lower():
        messages.error(request, "You don't have access to this department's directory.")
        return redirect('users:daily_activity')

    daily_reports = DailyActivityReport.objects.filter(user__department__name=department_name)

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )
    response['Content-Disposition'] = f'attachment; filename={department_name}_daily_reports.xlsx'

    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = f"{department_name} Reports"

    # Add headers
    headers = ["Date", "User", "Task", "News Count", "Total News Count"]
    worksheet.append(headers)

    # Populate data
    total_news_count = 0
    for report in daily_reports:
        total_news_count += report.news_count
        worksheet.append([report.date, report.user.username, report.task, report.news_count, total_news_count])

    workbook.save(response)
    return response

# Forgot password request page
def forgot_password(request):
    if request.method == 'POST':
        username_or_email = request.POST.get('username_or_email')
        CustomUser = get_user_model()
        
        try:
            user = CustomUser.objects.get(username=username_or_email)
        except ObjectDoesNotExist:
            try:
                user = CustomUser.objects.get(email=username_or_email)
            except ObjectDoesNotExist:
                messages.error(request, "User with this username or email does not exist.")
                return redirect('users:forgot_password')

        # Generate verification code
        verification_code = random.randint(100000, 999999)

        # Prepare email details
        admin_email = 'sathya9352@gmail.com'
        subject = f"Password Reset Request for {user.username}"
        department_name = user.department.name if user.department else "No department"
        message = f"""
        A password reset request has been made for the user {user.username}.
        Username : {user.username}
        Department: {department_name}
        Verification Code: {verification_code}
        """

        # Send email to admin
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [admin_email])

        # Store verification code and user ID in session
        request.session['verification_code'] = verification_code
        request.session['user_id'] = user.id

        messages.success(request, "A password reset request has been sent to the admin.")
        return redirect('users:verify_and_reset_password')

    return render(request, 'users/forgot_password.html')

# Admin view to verify the password reset request and reset the password
@login_required
def verify_and_reset_password(request):
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')
        new_password = request.POST.get('new_password')

        # Validate verification code
        if str(verification_code) == str(request.session.get('verification_code')):
            user_id = request.session.get('user_id')
            user = CustomUser.objects.get(id=user_id)
            
            # Update password
            user.set_password(new_password)
            user.save()

            messages.success(request, f"Password reset successfully for {user.username}.")
            return redirect('users:login')
        else:
            messages.error(request, "Invalid verification code.")
            return redirect('users:verify_and_reset_password')

    return render(request, 'users/verify_password_reset.html')

