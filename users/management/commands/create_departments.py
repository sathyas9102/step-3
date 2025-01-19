from django.core.management.base import BaseCommand
from users.models import Department

class Command(BaseCommand):
    help = 'Creates default departments'

    def handle(self, *args, **kwargs):
        department_names = ['Sales', 'Media', 'IT', 'Dovel', 'Brandsmart']
        for dept_name in department_names:
            Department.objects.get_or_create(name=dept_name, description=f"Description for {dept_name}")
        
        self.stdout.write(self.style.SUCCESS('Successfully created default departments'))
