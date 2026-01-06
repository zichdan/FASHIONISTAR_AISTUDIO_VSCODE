from rest_framework import generics, status, serializers
from rest_framework.response import Response
from apps.authentication.services.password_service import PasswordService
import logging

logger = logging.getLogger('application')

class PasswordResetRequestSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()
    
    class Meta:
        ref_name = 'AuthenticationPasswordResetRequest'

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField()
    
    class Meta:
        ref_name = 'AuthenticationPasswordResetConfirm'

class PasswordResetRequestView(generics.GenericAPIView):
    """
    API view for password reset request.
    """
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            message = PasswordService.request_password_reset(data['email_or_phone'])
            return Response({
                'success': True,
                'message': message
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password reset request error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Password reset request failed.',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(generics.GenericAPIView):
    """
    API view for password reset confirmation.
    """
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            message = PasswordService.confirm_password_reset(data['uidb64'], data['token'], data['new_password'])
            return Response({
                'success': True,
                'message': message
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password reset confirm error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Password reset confirmation failed.',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)