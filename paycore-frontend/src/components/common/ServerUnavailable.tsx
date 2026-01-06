import {
  Box,
  VStack,
  Heading,
  Text,
  Button,
  Icon,
  Link,
  useColorModeValue,
} from '@chakra-ui/react';
import { ExternalLinkIcon } from '@chakra-ui/icons';

interface ServerUnavailableProps {
  onRetry?: () => void;
}

/**
 * Component displayed when the backend server is unavailable or unreachable
 * Shows a friendly message with a crying emoji and link to backend repository
 */
export const ServerUnavailable: React.FC<ServerUnavailableProps> = ({ onRetry }) => {
  const bgColor = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.600');

  return (
    <Box
      position="fixed"
      top="0"
      left="0"
      right="0"
      bottom="0"
      display="flex"
      alignItems="center"
      justifyContent="center"
      bg={useColorModeValue('gray.50', 'gray.900')}
      zIndex="9999"
    >
      <VStack
        spacing={6}
        p={8}
        bg={bgColor}
        borderRadius="xl"
        borderWidth="1px"
        borderColor={borderColor}
        boxShadow="xl"
        maxW="500px"
        textAlign="center"
      >
        {/* Crying Emoji */}
        <Text fontSize="6xl" aria-label="crying face">
          😢
        </Text>

        {/* Heading */}
        <Heading size="lg" color={useColorModeValue('gray.800', 'gray.100')}>
          Server Unavailable
        </Heading>

        {/* Message */}
        <VStack spacing={3}>
          <Text color={useColorModeValue('gray.600', 'gray.300')} fontSize="md">
            The PayCore API server has been stopped and is now unreachable.
          </Text>
          <Text color={useColorModeValue('gray.600', 'gray.300')} fontSize="sm">
            This was a demonstration project hosted on a paid server. The live server was
            discontinued on <strong>February 14th, 2026</strong>.
          </Text>
        </VStack>

        {/* Action Buttons */}
        <VStack spacing={3} width="100%">
          {onRetry && (
            <Button colorScheme="blue" width="100%" onClick={onRetry}>
              Try Again
            </Button>
          )}

          <Link
            href="https://github.com/kayprogrammer/paycore-api-1"
            isExternal
            width="100%"
            _hover={{ textDecoration: 'none' }}
          >
            <Button
              variant="outline"
              colorScheme="gray"
              width="100%"
              rightIcon={<ExternalLinkIcon />}
            >
              View Backend Repository
            </Button>
          </Link>
        </VStack>

        {/* Additional Info */}
        <Text fontSize="xs" color={useColorModeValue('gray.500', 'gray.400')}>
          You can run the project locally by following the setup instructions in the repository.
        </Text>
      </VStack>
    </Box>
  );
};
