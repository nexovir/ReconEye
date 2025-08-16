from django.apps import AppConfig


class PrivateWatchersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'asset_monitor'

    def ready(self):
        import asset_monitor.signals
        import asset_monitor.signals

