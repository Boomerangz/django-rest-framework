from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _
from main.models import Client,AndroidApiKey
from rest_framework import exceptions, serializers


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})
    key = attrs.get('key')

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                client = Client.objects.get(user=user)
                if key:
                    try:
                        old_key = AndroidApiKey.objects.get(client_id=client.id)
                        old_key.key = key
                        old_key.save()
                    except AndroidApiKey.DoesNotExist:
                        AndroidApiKey.objects.create(client=client,key=key).save()
                if not client.email_confirmed:
                    raise exceptions.PermissionDenied()
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise exceptions.ValidationError(msg)
            else:
                msg = _('Unable to log in with provided credentials.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs
