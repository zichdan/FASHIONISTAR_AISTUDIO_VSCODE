# apps/authentication/apis/auth_views.py

from rest_framework import generics, status
from rest_framework.response import Response
from apps.authentication.services.auth_service import AuthService
from apps.authentication.types.auth_schemas import LoginSchema
from rest_framework import serializers
import logging

logger = logging.getLogger('application')

class LoginSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()
    password = serializers.CharField()
    
    class Meta:
        ref_name = 'AuthenticationLogin'

class LoginView(generics.GenericAPIView):
    """
    API view for user login.
    """
    serializer_class = LoginSerializer

    def post(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            
            # Create a simple object with the data
            class LoginData:
                def __init__(self, email_or_phone, password):
                    self.email_or_phone = email_or_phone
                    self.password = password
            
            login_data = LoginData(data['email_or_phone'], data['password'])
            tokens = AuthService.login(login_data, request)
            return Response({
                'success': True,
                'message': 'Login successful.',
                'data': tokens
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Login view error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Login failed.',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

# Similarly for register, logout, etc.