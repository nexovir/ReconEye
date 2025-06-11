import graphene
import users.schema
from writeups.schema import *
from tools.schema import *
from techniques.schema import *

class Query(graphene.ObjectType):
    hello = graphene.String(default_value="Hello Hacker!")

class Mutation(users.schema.Mutation, graphene.ObjectType):
    create_writeup = CreateWriteUp.Field()
    update_writeup = UpdateWriteup.Field()
    delete_writeup = DeleteWriteup.Field()
    create_tool = CreateTool.Field()
    update_tool = UpdateTool.Field()
    delete_tool = DeleteTool.Field()
    create_technique = CreateTechnique.Field()
    update_technique = UpdateTechnique.Field()
    delete_technique = DeleteTechnique.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)
