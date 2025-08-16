from django.contrib import admin
from django.contrib.admin import register
from .models import *

@register(Url)
class UrlAdmin(admin.ModelAdmin):
    list_display = ['subdomain' , 'url' , 'label', 'ext' , 'body_hash']
    search_fields = ['subdomain' , 'url']

@register(UrlChanges)
class UrlChangesAdmin(admin.ModelAdmin):
    list_display = ['url', 'label' , 'old_body_hash' , 'new_body_hash']
    search_fields = ['url']


