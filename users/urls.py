from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    path('', views.custom_login, name='login'),
    path('daily_activity/<str:department_name>/', views.daily_activity_department, name='daily_activity_department'),
    path('export_excel/<str:department_name>/', views.export_excel_department, name='export_excel_department'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('verify_and_reset_password/', views.verify_and_reset_password, name='verify_and_reset_password'),
]
