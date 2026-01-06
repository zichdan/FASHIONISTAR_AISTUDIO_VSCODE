import {
  Container,
  VStack,
  Box,
  Heading,
  Text,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Button,
} from '@chakra-ui/react';
import { useNavigate } from 'react-router-dom';

interface KYCRequiredProps {
  title?: string;
  description?: string;
}

export const KYCRequired = ({
  title = 'KYC Verification Required',
  description = 'To access this feature, you need to complete your KYC verification first.',
}: KYCRequiredProps) => {
  const navigate = useNavigate();

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={6} align="stretch">
        <Alert
          status="warning"
          variant="subtle"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          textAlign="center"
          minHeight="400px"
          borderRadius="xl"
        >
          <AlertIcon boxSize="40px" mr={0} />
          <AlertTitle mt={4} mb={1} fontSize="lg">
            {title}
          </AlertTitle>
          <AlertDescription maxWidth="md" mb={4}>
            {description}
          </AlertDescription>
          <Button
            colorScheme="orange"
            size="lg"
            onClick={() => navigate('/profile')}
          >
            Complete Verification
          </Button>
        </Alert>
      </VStack>
    </Container>
  );
};
