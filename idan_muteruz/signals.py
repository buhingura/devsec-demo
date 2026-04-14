from django.conf import settings
from django.contrib.auth.models import Group
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Profile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
            display_name=instance.get_full_name() or instance.username,
        )
        # Place every new user in the "students" group (default role).
        # If the group does not exist yet (i.e. setup_groups hasn't been run),
        # this is silently skipped — no error is raised.
        try:
            students_group = Group.objects.get(name='students')
            instance.groups.add(students_group)
        except Group.DoesNotExist:
            pass
    else:
        Profile.objects.get_or_create(user=instance)
