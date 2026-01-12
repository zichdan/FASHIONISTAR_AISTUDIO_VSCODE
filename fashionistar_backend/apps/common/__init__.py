# apps/common/__init__.py
"""
Common app for the Fashionistar project.

This app provides shared utilities, models, permissions, and exceptions
for the entire modular monolith architecture.

Key Components:
- models.py: Base models (TimeStampedModel, SoftDeleteModel, HardDeleteMixin)
- permissions.py: Granular RBAC permissions
- exceptions.py: Custom exception handlers
- renderers.py: Standardized API response formatters
- managers/: Email and SMS managers with async support
- providers/: SMTP and SMS provider implementations
- utils.py: Shared utility functions
"""