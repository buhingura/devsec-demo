from django.apps import AppConfig


class IdanMuteruzConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'idan_muteruz'
    verbose_name = 'Authentication'

    def ready(self):
        import idan_muteruz.signals  # noqa: F401
