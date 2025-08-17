from django.contrib import admin
from django.contrib.admin import register
from .models import *
from django.utils.html import format_html


@register(Url)
class UrlAdmin(admin.ModelAdmin):
    list_display = ['subdomain' , 'path' , 'query' , 'label', 'ext' , 'short_url']
    search_fields = ['subdomain' , 'path']
    list_filter = ['label' , 'ext']
    ordering = ['-label']

    def short_url(self, obj):
        return format_html('<a href="{}" target="_blank">Click here</a>', obj.url)
    short_url.short_description = 'URL'

@register(UrlChanges)
class UrlChangesAdmin(admin.ModelAdmin):
    list_display = ['url' , 'body_hash_change' , 'ext', 'label' ,'short_url']
    search_fields = ['path_change']
    ordering = ['-label']
    
    def short_url(self, obj):
        return format_html('<a href="{}" target="_blank">Click here</a>', obj.url.url)
    short_url.short_description = 'URL'
