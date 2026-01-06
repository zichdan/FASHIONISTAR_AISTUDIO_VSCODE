# apps/authentication/management/commands/migrate_v1_users.py

from django.core.management.base import BaseCommand
from userauths.models import User as OldUser, Profile
from apps.authentication.models import UnifiedUser as NewUser
import logging

logger = logging.getLogger('application')

class Command(BaseCommand):
    help = 'Migrate users from old userauths to new authentication app'

    def handle(self, *args, **options):
        try:
            for old_user in OldUser.objects.all():
                profile = Profile.objects.filter(user=old_user).first()
                NewUser.objects.create(
                    email=old_user.email,
                    phone=profile.phone if profile else None,
                    # ... other fields
                )
            self.stdout.write(self.style.SUCCESS('Migration completed'))
        except Exception as e:
            logger.error(f"Migration error: {str(e)}")
            raise