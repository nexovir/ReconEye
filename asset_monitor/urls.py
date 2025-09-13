from django.urls import path
from . import views

urlpatterns = [
    path('wildcard/<int:wildcard_id>/download/', views.download_wildcard_params, name='download_wildcard_params'),
]
