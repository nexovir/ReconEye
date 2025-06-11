# core/models.py

from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericRelation
from interactions.models import *


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True



class AttributesBaseModel(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    slug = models.SlugField(unique=True , max_length=250)
    title = models.CharField(max_length=200, unique=True)

    content = models.TextField(blank=False , null=False , max_length=2000)
    preview_text = models.TextField(blank=False , null=False , max_length=500)
    
    price = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    is_free = models.BooleanField(default=False)
    purchase_count = models.PositiveIntegerField(default=0)
 
    is_public = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)

    likes = GenericRelation(Like)
    comments = GenericRelation(Comment)
    rating = GenericRelation(Rating)
    watch = GenericRelation(Watch)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True
