from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import *

def download_wildcard_params(request, wildcard_id):
    wildcard = get_object_or_404(WatchedWildcard, pk=wildcard_id)
    return export_wildcard_parameters_txt(wildcard)


def download_wildcard_urls(request, wildcard_id):
    wildcard = get_object_or_404(WatchedWildcard, pk=wildcard_id)
    return export_wildcard_urls_txt(wildcard)