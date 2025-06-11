from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.contrib.auth.models import User

RATING_CHOICES = [
    (1, 'Very Poor'),
    (2, 'Poor'),
    (3, 'Average'),
    (4, 'Good'),
    (5, 'Excellent'),
]
class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True


class Like(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    def __str__ (self):
        return f"{self.user} - {self.content_type} - {self.content_object}"

    class Meta : 
        verbose_name = 'Like'
        verbose_name_plural = 'Likes'
        unique_together = ('user', 'content_type', 'object_id')


        
class Comment(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")
    text = models.TextField()

    def __str__ (self):
        return f"{self.user} - {self.content_type} - {self.content_object}"

    class Meta : 
        verbose_name = 'Comment'
        verbose_name_plural = 'Comments'




class Rating(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings')
    score = models.PositiveSmallIntegerField(choices=RATING_CHOICES)
    comment = models.TextField(blank=True, null=True)

    # Generic relation to Tool, Technique, or ZeroDay
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')


    class Meta:
        unique_together = ('user', 'content_type', 'object_id')  # Prevent duplicate ratings
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} rated {self.content_object} as {self.score}"



class Watch(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='watch')

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')


    class Meta:
        unique_together = ('user', 'content_type', 'object_id')  # Prevent duplicate ratings
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} rated {self.content_object} as {self.score}"
