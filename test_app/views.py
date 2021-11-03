from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser, AllowAny
from .serializers import GroupSerializer, RegistrationSerializer, ObtainTokenSerializer, PermissionSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User, Group, Permission
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.contenttypes.models import ContentType


class CreateGroupView(generics.CreateAPIView):
    permission_classes = (IsAdminUser, )

    def post(self, request):
        serializer = GroupSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Role created successfully", "data":serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RegistrationView(generics.CreateAPIView):
    permission_classes = (IsAdminUser, )

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User Created Successfully.", "user": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = ObtainTokenSerializer


class GroupList(generics.ListAPIView):
    permission_classes = (IsAdminUser,)
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


class AddPermission(generics.CreateAPIView):
    permission_classes = (IsAdminUser, )

    def post(self, request):
        permission_name = request.data.get('permission_name')
        code_name = request.data.get('code_name')
        group_name = request.data.get('group_name')

        try:
            group = Group.objects.get(name = group_name)
        except ObjectDoesNotExist:
            return Response({'Error': 'Group name does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        content_type = ContentType.objects.get_for_model(User)

        try:
            permission = Permission.objects.get(codename = code_name, name = permission_name, content_type = content_type)
        except ObjectDoesNotExist:
            permission = Permission.objects.create(codename = code_name, name = permission_name, content_type = content_type)

        serializer = PermissionSerializer(permission)
        if serializer.is_valid:
            group.permissions.add(permission)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

