from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import GroupSerializer, RegistrationSerializer, ObtainTokenSerializer, PermissionSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User, Group, Permission
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied


def getPermission(request, groups):
    if not request.user.is_authenticated:
        raise PermissionDenied
    else:
        user_groups = []
        for group in request.user.groups.values_list('name', flat=True):
            user_groups.append(group)
        if len(set(user_groups).intersection(groups)) <= 0:
            raise PermissionDenied
    return True


class CreateGroupView(generics.CreateAPIView):
    def post(self, request):
        getPermission(request, ['admin'])

        serializer = GroupSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Role created successfully", "data":serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RegistrationView(generics.CreateAPIView):
    def post(self, request):
        getPermission(request, ['admin'])

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
    def get(self, request):
        getPermission(request, ['admin'])

        queryset = Group.objects.all()
        serializer = GroupSerializer(queryset, many=True)

        if serializer.is_valid:
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AddPermission(generics.CreateAPIView):
    def post(self, request):
        getPermission(request, ['admin'])

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

