# apps/common/renderers.py

from rest_framework.renderers import JSONRenderer
import logging

logger = logging.getLogger('application')

class CustomJSONRenderer(JSONRenderer):
    """
    Custom JSON renderer for standardized API responses.
    """
    def render(self, data, accepted_media_type=None, renderer_context=None):
        try:
            response = renderer_context.get('response', None)
            if response and hasattr(response, 'status_code'):
                if response.status_code >= 400:
                    # Error response
                    error_data = {
                        'success': False,
                        'message': data.get('detail', 'An error occurred'),
                        'error': data
                    }
                    return super().render(error_data, accepted_media_type, renderer_context)
                else:
                    # Success response
                    success_data = {
                        'success': True,
                        'message': 'Request successful',
                        'data': data
                    }
                    return super().render(success_data, accepted_media_type, renderer_context)
            return super().render(data, accepted_media_type, renderer_context)
        except Exception as e:
            logger.error(f"Error in custom renderer: {str(e)}")
            return super().render(data, accepted_media_type, renderer_context)