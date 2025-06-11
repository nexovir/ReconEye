import graphene
from graphene_django.types import DjangoObjectType
from .models import *


class WriteupCategoryType(DjangoObjectType):
    class Meta:
        model = WriteupCategory
        fields = '__all__'


class WriteUpType(DjangoObjectType):
    class Meta:
        model = WriteUp
        fields = '__all__'


class CreateWriteUp(graphene.Mutation):
    class Arguments:
        title = graphene.String(required=True)
        category_id = graphene.Int(required=True)
        content = graphene.String(required=True)
        preview_text = graphene.String(required=True)
        price = graphene.Decimal(required=False)
        is_public = graphene.Boolean(required=False, default_value=False)
        vulnerability_type = graphene.String(required=True)
        target_type = graphene.String(required=True)
        tools_used = graphene.List(graphene.Int, required=False)
        techniques = graphene.List(graphene.Int, required=False)
        read_time = graphene.Int(required=False, default_value=3)
        
    writeup = graphene.Field(WriteUpType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, title, category_id, content, preview_text, price,
               vulnerability_type=None, target_type=None, tools_used=True, techniques=None, read_time="", is_public=False):

        user = info.context.user
        if user.is_anonymous:
            raise Exception("Authentication required")

        try:
            category = WriteupCategory.objects.get(id=category_id)
        except WriteupCategory.DoesNotExist:
            raise Exception("Invalid category")

        writeup = WriteUp.objects.create(
            title=title,
            category=category,
            content=content,
            preview_text=preview_text,
            author=user,
            price=price,
            is_public=is_public,
            vulnerability_type=vulnerability_type,
            target_type=target_type,
            read_time=read_time,
        )

        if tools_used:
            writeup.tools_used.set(Tool.objects.filter(id__in=tools_used))

        if techniques:
            writeup.techniques.set(Techniques.objects.filter(id__in=techniques))

        return CreateWriteUp(writeup=writeup)



class UpdateWriteup(graphene.Mutation):
    class Arguments:
        writeup_id = graphene.Int(required=True)
        title = graphene.String(required=True)
        category_id = graphene.Int(required=True)
        content = graphene.String(required=True)
        preview_text = graphene.String(required=True)
        price = graphene.Decimal(required=False)
        is_public = graphene.Boolean(required=False, default_value=False)
        vulnerability_type = graphene.String(required=True)
        target_type = graphene.String(required=True)
        tools_used = graphene.List(graphene.Int, required=False)
        techniques = graphene.List(graphene.Int, required=False)
        read_time = graphene.Int(required=False, default_value=3)

    writeup = graphene.Field(WriteUpType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, writeup_id, title, category_id, content, preview_text,
               price=None, is_public=False, vulnerability_type=None, target_type=None,
               tools_used=None, techniques=None, read_time=3):

        user = info.context.user
        if user.is_anonymous:
            raise Exception("Authentication required")

        try:
            writeup = WriteUp.objects.get(id=writeup_id, author=user)
        except WriteUp.DoesNotExist:
            raise Exception("Writeup not found or permission denied")

        try:
            category = WriteupCategory.objects.get(id=category_id)
        except WriteupCategory.DoesNotExist:
            raise Exception("Invalid category")

        # Update fields
        writeup.title = title
        writeup.category = category
        writeup.content = content
        writeup.preview_text = preview_text
        writeup.price = price
        writeup.is_public = is_public
        writeup.vulnerability_type = vulnerability_type
        writeup.target_type = target_type
        writeup.read_time = read_time
        writeup.save()

        # Set many-to-many fields if provided
        if tools_used is not None:
            writeup.tools_used.set(Tool.objects.filter(id__in=tools_used))

        if techniques is not None:
            writeup.techniques.set(Techniques.objects.filter(id__in=techniques))

        return UpdateWriteup(
            writeup=writeup,
            success=True,
            message="Writeup updated successfully"
        )


class DeleteWriteup(graphene.Mutation):
    class Arguments:
        writeup_id = graphene.Int(required=True)

    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, writeup_id):
        user = info.context.user
        if user.is_anonymous:
            raise Exception("Authentication required")

        try:
            writeup = WriteUp.objects.get(id=writeup_id, author=user)
        except WriteUp.DoesNotExist:
            raise Exception("Writeup not found or permission denied")

        writeup.delete()

        return DeleteWriteup(success=True, message="Writeup deleted successfully")
