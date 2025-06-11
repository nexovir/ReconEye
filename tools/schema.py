import graphene
from graphene_django.types import DjangoObjectType
from .models import Tool, ToolCategory


class ToolCategoryType(DjangoObjectType):
    class Meta:
        model = ToolCategory
        fields = '__all__'


class ToolType(DjangoObjectType):
    class Meta:
        model = Tool
        fields = '__all__'


class CreateTool(graphene.Mutation):
    class Arguments:
        title = graphene.String(required=True)
        content = graphene.String(required=True)
        category_id = graphene.Int(required=True)
        upload_file = graphene.String(required=False)
        preview_text = graphene.String(required=True)
        demo_video_file = graphene.String(required=False)
        demo_video_url = graphene.String(required=False)
        github_repo_url = graphene.String(required=True)
        access_token = graphene.String(required=False)
        price = graphene.Decimal(required=False)
        is_public = graphene.Boolean(default_value=False)

    tool = graphene.Field(ToolType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, title, content, category_id, upload_file=None, preview_text="", demo_video_file=None,
               demo_video_url=None, github_repo_url="", access_token=None, price=None,  is_public=False):

        user = info.context.user
        if user.is_anonymous:
            return CreateTool(success=False, message="authentication required")

        try:
            category = ToolCategory.objects.get(id=category_id)
        except ToolCategory.DoesNotExist:
            return CreateTool(success=False, message="category not found")

        tool = Tool.objects.create(
            title=title,
            content=content,
            category=category,
            upload_file=upload_file,
            preview_text=preview_text,
            demo_video_file=demo_video_file,
            demo_video_url=demo_video_url,
            github_repo_url=github_repo_url,
            access_token=access_token,
            price=price,
            is_public=is_public,
            author=user,
            approved=False
        )

        return CreateTool(success=True, message="tool created successfully", tool=tool)



class UpdateTool(graphene.Mutation):
    class Arguments:
        tool_id = graphene.ID(required=True)
        title = graphene.String()
        content = graphene.String()
        category_id = graphene.Int()
        upload_file = graphene.String()
        preview_text = graphene.String()
        demo_video_file = graphene.String()
        demo_video_url = graphene.String()
        github_repo_url = graphene.String()
        access_token = graphene.String()
        price = graphene.Decimal()
        is_public = graphene.Boolean()

    tool = graphene.Field(ToolType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, tool_id, **kwargs):
        
        user = info.context.user
        if user.is_anonymous:
            return UpdateTool(success=False, message="authentication required")

        try:
            tool = Tool.objects.get(id=tool_id)
        except Tool.DoesNotExist:
            return UpdateTool(success=False, message="tool not found")

        if tool.author != user:
            return UpdateTool(success=False, message="not permitted to update this tool")

        category_id = kwargs.pop('category_id', None)
        if category_id is not None:
            try:
                category = ToolCategory.objects.get(id=category_id)
                tool.category = category
            except ToolCategory.DoesNotExist:
                return UpdateTool(success=False, message="category not found")

        for key, value in kwargs.items():
            if value is not None:
                setattr(tool, key, value)

        tool.save()

        return UpdateTool(success=True, message="tool updated successfully", tool=tool)



class DeleteTool(graphene.Mutation):
    class Arguments:
        tool_id = graphene.ID(required=True)

    success = graphene.Boolean()
    message = graphene.String() 

    def mutate(self, info, tool_id):
        user = info.context.user

        if user.is_anonymous:
            return DeleteTool(success=False, message="authentication required")

        try:
            tool = Tool.objects.get(id=tool_id)
        except Tool.DoesNotExist:
            return DeleteTool(success=False, message="tool not found")

        if tool.author != user:
            return DeleteTool(success=False, message="you are not allowed to delete this tool.")

        tool.delete()
        return DeleteTool(success=True, message="tool deleted successfully.")
