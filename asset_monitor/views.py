from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import WatchedWildcard, export_wildcard_parameters_txt

def download_wildcard_params(request, wildcard_id):
    wildcard = get_object_or_404(WatchedWildcard, pk=wildcard_id)
    return export_wildcard_parameters_txt(wildcard)
