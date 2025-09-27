from django.urls import path
from . import views

urlpatterns = [
    path('wildcard/<int:wildcard_id>/download/parameters', views.download_wildcard_params, name='download_wildcard_params'),
    path('wildcard/<int:wildcard_id>/download/urls', views.download_wildcard_urls, name='download_wildcard_urls'),
]
