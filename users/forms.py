from django import forms
from .models import CustomUser, DailyActivityReport

class CustomUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'is_admin', 'department']
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user

class DailyActivityReportForm(forms.ModelForm):
    class Meta:
        model = DailyActivityReport
        fields = ['task', 'news_count', 'insta_followers']
