from django.apps import AppConfig


class WatchersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'programs_monitor'

    def ready(self):
        import programs_monitor.tasks
        