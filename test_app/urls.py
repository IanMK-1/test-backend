from django.urls import path
from .views import CreateGroupView, LoginView, RegistrationView, GroupList, AddPermission

urlpatterns = [
    path('auth/login', LoginView.as_view(), name="login"),
    path('auth/register', RegistrationView.as_view(), name="register"),
    path('create/group', CreateGroupView.as_view(), name="create_group"),
    path('groups', GroupList.as_view(), name="group_list"),
    path('add/permission', AddPermission.as_view(), name='add_permission')
]