import { Box, VStack, Text, Icon, Button } from '@chakra-ui/react';
import { FiInbox } from 'react-icons/fi';

interface EmptyStateProps {
  icon?: React.ElementType;
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState = ({
  icon: IconComponent = FiInbox,
  title,
  description,
  actionLabel,
  onAction,
}: EmptyStateProps) => {
  return (
    <Box py={12}>
      <VStack spacing={4}>
        <Icon as={IconComponent} boxSize={12} color="gray.400" />
        <VStack spacing={2}>
          <Text fontSize="lg" fontWeight="600" color="gray.700">
            {title}
          </Text>
          {description && (
            <Text fontSize="sm" color="gray.500" textAlign="center" maxW="md">
              {description}
            </Text>
          )}
        </VStack>
        {actionLabel && onAction && (
          <Button onClick={onAction} mt={4}>
            {actionLabel}
          </Button>
        )}
      </VStack>
    </Box>
  );
};
