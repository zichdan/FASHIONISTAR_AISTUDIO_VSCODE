import { Box, Container, Flex, Text, VStack } from '@chakra-ui/react';

interface AuthLayoutProps {
  children: React.ReactNode;
}

export const AuthLayout = ({ children }: AuthLayoutProps) => {
  return (
    <Flex minH="100vh" bg="gray.50">
      {/* Left Side - Branding */}
      <Flex
        w="50%"
        bg="brand.500"
        display={{ base: 'none', lg: 'flex' }}
        align="center"
        justify="center"
        p={12}
      >
        <VStack spacing={6} color="white" maxW="md">
          <Text fontSize="5xl" fontWeight="bold">
            PayCore
          </Text>
          <Text fontSize="2xl" textAlign="center" fontWeight="300">
            Your Complete Fintech Solution
          </Text>
          <Text fontSize="md" textAlign="center" opacity={0.9}>
            Manage wallets, cards, investments, loans, and more in one secure platform.
          </Text>
        </VStack>
      </Flex>

      {/* Right Side - Auth Form */}
      <Flex w={{ base: '100%', lg: '50%' }} align="center" justify="center" p={8}>
        <Container maxW="md" w="full">
          <Box bg="white" p={8} borderRadius="2xl" boxShadow="lg">
            {children}
          </Box>
        </Container>
      </Flex>
    </Flex>
  );
};

export default AuthLayout;
