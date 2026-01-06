import { useState } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Container,
  Heading,
  VStack,
  Text,
  FormControl,
  FormLabel,
  Input,
  Button,
  Card,
  CardBody,
  useToast,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Spinner,
  Center,
  Badge,
  Divider,
  Select,
} from '@chakra-ui/react';
import { FiCheckCircle, FiLock } from 'react-icons/fi';
import { useGetPaymentLinkBySlugQuery, usePayPaymentLinkMutation } from '@/features/payments/services/paymentsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { useAppSelector } from '@/hooks';
import { selectIsAuthenticated } from '@/store/slices/authSlice';

export const PaymentLinkPublicPage = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const isAuthenticated = useAppSelector(selectIsAuthenticated);
  const [paymentComplete, setPaymentComplete] = useState(false);

  // Fetch payment link details using the public endpoint (no auth required)
  const { data: linkData, isLoading, error } = useGetPaymentLinkBySlugQuery(slug || '');
  const { data: walletsData } = useListWalletsQuery(undefined, { skip: !isAuthenticated });
  const [payPaymentLink, { isLoading: isProcessing }] = usePayPaymentLinkMutation();

  const [formData, setFormData] = useState({
    wallet_id: '',
    amount: '',
  });

  const link = linkData?.data;

  // Filter wallets to only show those matching the payment link currency
  const compatibleWallets = walletsData?.data?.filter((wallet: any) =>
    wallet.currency.code === link?.currency?.code
  ) || [];

  const handleLoginRedirect = () => {
    navigate(`/login?next=${encodeURIComponent(location.pathname)}`);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!link) return;

    // Check if user is authenticated before submitting payment
    if (!isAuthenticated) {
      toast({
        title: 'Login Required',
        description: 'Please login to complete your payment',
        status: 'warning',
        duration: 3000,
      });
      handleLoginRedirect();
      return;
    }

    if (!formData.wallet_id) {
      toast({
        title: 'Wallet Required',
        description: 'Please select a wallet to pay from',
        status: 'error',
        duration: 3000,
      });
      return;
    }

    try {
      await payPaymentLink({
        slug: slug || '',
        data: {
          wallet_id: formData.wallet_id,
          amount: link.amount || parseFloat(formData.amount),
        },
      }).unwrap();

      setPaymentComplete(true);

      toast({
        title: 'Payment Successful!',
        description: 'Your payment has been processed successfully.',
        status: 'success',
        duration: 5000,
        isClosable: true,
      });

      // Redirect after 3 seconds
      setTimeout(() => {
        if (link.redirect_url) {
          window.location.href = link.redirect_url;
        } else {
          navigate('/dashboard');
        }
      }, 3000);
    } catch (err: any) {
      console.error('Payment error:', err);

      // Extract error message from nested structure
      let errorMessage = 'Failed to process payment. Please try again.';

      if (err?.data?.data && typeof err.data.data === 'object') {
        // Handle validation errors (e.g., { wallet_id: "error message" })
        const validationErrors = Object.values(err.data.data);
        if (validationErrors.length > 0) {
          errorMessage = validationErrors.join(', ');
        }
      } else if (err?.data?.message) {
        errorMessage = err.data.message;
      } else if (err?.message) {
        errorMessage = err.message;
      }

      toast({
        title: 'Payment Failed',
        description: errorMessage,
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    }
  };

  if (isLoading) {
    return (
      <Center h="100vh">
        <VStack spacing={4}>
          <Spinner size="xl" color="brand.500" thickness="4px" />
          <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>Loading payment details...</Text>
        </VStack>
      </Center>
    );
  }

  if (error || !link) {
    return (
      <Container maxW="container.sm" py={{ base: 10, md: 20 }} px={{ base: 4, md: 6 }}>
        <Alert
          status="error"
          variant="subtle"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          textAlign="center"
          borderRadius="lg"
          py={{ base: 6, md: 10 }}
        >
          <AlertIcon boxSize={{ base: '30px', md: '40px' }} mr={0} />
          <AlertTitle mt={4} mb={1} fontSize={{ base: 'md', md: 'lg' }}>
            Payment Link Not Found
          </AlertTitle>
          <AlertDescription maxWidth="sm" fontSize={{ base: 'sm', md: 'md' }}>
            This payment link is invalid, expired, or has been removed.
          </AlertDescription>
        </Alert>
      </Container>
    );
  }

  if (paymentComplete) {
    return (
      <Container maxW="container.sm" py={{ base: 10, md: 20 }} px={{ base: 4, md: 6 }}>
        <Alert
          status="success"
          variant="subtle"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          textAlign="center"
          borderRadius="lg"
          py={{ base: 6, md: 10 }}
        >
          <AlertIcon as={FiCheckCircle} boxSize={{ base: '30px', md: '40px' }} mr={0} />
          <AlertTitle mt={4} mb={1} fontSize={{ base: 'md', md: 'lg' }}>
            Payment Successful!
          </AlertTitle>
          <AlertDescription maxWidth="sm" fontSize={{ base: 'sm', md: 'md' }}>
            Your payment has been processed successfully. The merchant has been credited.
          </AlertDescription>
        </Alert>
      </Container>
    );
  }

  return (
    <Box bg="gray.50" minH="100vh" py={{ base: 8, md: 20 }}>
      <Container maxW="container.sm" px={{ base: 4, md: 6 }}>
        <VStack spacing={{ base: 4, md: 6 }} align="stretch">
          {/* Payment Link Info */}
          <Card>
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Box textAlign="center">
                  <Badge colorScheme="brand" mb={2} fontSize={{ base: 'xs', md: 'sm' }}>
                    Payment Request
                  </Badge>
                  <Heading size={{ base: 'md', md: 'lg' }} mb={2}>
                    {link.title}
                  </Heading>
                  {link.description && (
                    <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>
                      {link.description}
                    </Text>
                  )}
                </Box>

                <Divider />

                {link.amount ? (
                  <Box textAlign="center" py={{ base: 3, md: 4 }}>
                    <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600" mb={2}>
                      Amount to Pay
                    </Text>
                    <Heading size={{ base: 'xl', md: '2xl' }} color="brand.600">
                      {parseFloat(link.amount).toLocaleString('en-US', {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2,
                      })}
                    </Heading>
                    <Text fontSize="xs" color="gray.500" mt={2}>
                      + 1.5% processing fee
                    </Text>
                  </Box>
                ) : (
                  <FormControl isRequired>
                    <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Enter Amount</FormLabel>
                    <Input
                      type="number"
                      step="0.01"
                      placeholder="0.00"
                      value={formData.amount}
                      onChange={(e) => setFormData({ ...formData, amount: e.target.value })}
                      size={{ base: 'md', md: 'lg' }}
                    />
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      A 1.5% processing fee will be added
                    </Text>
                  </FormControl>
                )}
              </VStack>
            </CardBody>
          </Card>

          {/* Payment Form */}
          <Card>
            <CardBody>
              {!isAuthenticated ? (
                <VStack spacing={4} align="stretch">
                  <Heading size={{ base: 'sm', md: 'md' }} mb={2}>
                    Ready to Pay?
                  </Heading>

                  <Alert status="info" borderRadius="md">
                    <AlertIcon as={FiLock} />
                    <Box>
                      <AlertTitle fontSize={{ base: 'xs', md: 'sm' }}>Login Required</AlertTitle>
                      <AlertDescription fontSize="xs">
                        You need to login to complete this payment. After logging in, you'll be redirected back to this page.
                      </AlertDescription>
                    </Box>
                  </Alert>

                  <Button
                    leftIcon={<FiLock />}
                    colorScheme="brand"
                    size={{ base: 'md', md: 'lg' }}
                    onClick={handleLoginRedirect}
                  >
                    Login to Pay
                  </Button>

                  <Text fontSize="xs" color="gray.500" textAlign="center">
                    Don't have an account? <Button variant="link" colorScheme="brand" fontSize="xs" onClick={() => navigate(`/register?next=${encodeURIComponent(location.pathname)}`)}>Sign up</Button>
                  </Text>
                </VStack>
              ) : (
                <form onSubmit={handleSubmit}>
                  <VStack spacing={4} align="stretch">
                    <Heading size={{ base: 'sm', md: 'md' }} mb={2}>
                      Payment Details
                    </Heading>

                    <FormControl isRequired>
                      <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Select Wallet</FormLabel>
                      {compatibleWallets.length === 0 ? (
                        <Alert status="warning" borderRadius="md">
                          <AlertIcon />
                          <Box>
                            <AlertTitle fontSize="sm">No Compatible Wallet</AlertTitle>
                            <AlertDescription fontSize="xs">
                              You don't have a wallet in {link?.currency?.code} currency. Please create one first.
                            </AlertDescription>
                          </Box>
                        </Alert>
                      ) : (
                        <>
                          <Select
                            placeholder="Choose a wallet to pay from"
                            value={formData.wallet_id}
                            onChange={(e) => setFormData({ ...formData, wallet_id: e.target.value })}
                          >
                            {compatibleWallets.map((wallet: any) => (
                              <option key={wallet.wallet_id} value={wallet.wallet_id}>
                                {wallet.currency.name} ({wallet.currency.code}) - Balance: {parseFloat(wallet.balance).toLocaleString()}
                              </option>
                            ))}
                          </Select>
                          <Text fontSize="xs" color="gray.500" mt={1}>
                            Make sure your wallet has sufficient balance
                          </Text>
                        </>
                      )}
                    </FormControl>

                    <Button
                      type="submit"
                      colorScheme="brand"
                      size={{ base: 'md', md: 'lg' }}
                      isLoading={isProcessing}
                      loadingText="Processing Payment..."
                      isDisabled={compatibleWallets.length === 0}
                      mt={2}
                    >
                      Complete Payment
                    </Button>
                  </VStack>
                </form>
              )}
            </CardBody>
          </Card>

          <Text fontSize="xs" color="gray.500" textAlign="center">
            Secured by PayCore • Payments are processed instantly
          </Text>
        </VStack>
      </Container>
    </Box>
  );
};
