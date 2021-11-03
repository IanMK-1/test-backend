from rest_framework import serializers
from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class GroupSerializer(serializers.ModelSerializer):    
    class Meta:
        model = Group
        fields = ('id','name',)


class PermissionSerializer(serializers.ModelSerializer):    
    class Meta:
        model = Permission
        fields = '__all__'


class RegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name', 'groups')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'groups': {'required': True}
        }
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()

        groups_data = validated_data.pop('groups')
        for group_data in groups_data:
            group = Group.objects.get(name=group_data)
            user.groups.add(group)

        return user


class ObtainTokenSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super(ObtainTokenSerializer, cls).get_token(user)
        group_set = Group.objects.filter(user = user)
        serializer = GroupSerializer(group_set, many=True)

        # Add custom claims
        token['username'] = user.username
        token['groups'] = serializer.data
        return token
