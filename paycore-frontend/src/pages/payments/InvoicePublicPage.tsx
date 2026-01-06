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
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  TableContainer,
  HStack,
} from '@chakra-ui/react';
import { FiCheckCircle, FiLock, FiFileText } from 'react-icons/fi';
import { useGetInvoiceByNumberQuery, usePayInvoiceMutation } from '@/features/payments/services/paymentsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { useAppSelector } from '@/hooks';
import { selectIsAuthenticated } from '@/store/slices/authSlice';

export const InvoicePublicPage = () => {
  const { invoice_number } = useParams<{ invoice_number: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const isAuthenticated = useAppSelector(selectIsAuthenticated);
  const [paymentComplete, setPaymentComplete] = useState(false);

  // Fetch invoice details using the public endpoint (no auth required)
  const { data: invoiceData, isLoading, error } = useGetInvoiceByNumberQuery(invoice_number || '');
  const { data: walletsData } = useListWalletsQuery(undefined, { skip: !isAuthenticated });
  const [payInvoice, { isLoading: isProcessing }] = usePayInvoiceMutation();

  const [formData, setFormData] = useState({
    wallet_id: '',
  });

  const invoice = invoiceData?.data;

  // Filter wallets to only show those matching the invoice currency
  const compatibleWallets = walletsData?.data?.filter((wallet: any) =>
    wallet.currency.code === invoice?.currency?.code
  ) || [];

  // Get currency symbol safely
  const currencySymbol = invoice?.currency?.symbol || '$';

  const handleLoginRedirect = () => {
    navigate(`/login?next=${encodeURIComponent(location.pathname)}`);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!invoice) return;

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
      await payInvoice({
        invoice_number: invoice_number || '',
        data: {
          wallet_id: formData.wallet_id,
        },
      }).unwrap();

      setPaymentComplete(true);

      toast({
        title: 'Payment Successful!',
        description: 'Your invoice payment has been processed successfully.',
        status: 'success',
        duration: 5000,
        isClosable: true,
      });

      // Redirect after 3 seconds
      setTimeout(() => {
        navigate('/dashboard');
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
          <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>Loading invoice details...</Text>
        </VStack>
      </Center>
    );
  }

  if (error || !invoice) {
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
            Invoice Not Found
          </AlertTitle>
          <AlertDescription maxWidth="sm" fontSize={{ base: 'sm', md: 'md' }}>
            This invoice is invalid, has been paid, or has been removed.
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
            Your invoice payment has been processed successfully. The merchant has been credited.
          </AlertDescription>
        </Alert>
      </Container>
    );
  }

  return (
    <Box bg="gray.50" minH="100vh" py={{ base: 8, md: 20 }}>
      <Container maxW="container.md" px={{ base: 4, md: 6 }}>
        <VStack spacing={{ base: 4, md: 6 }} align="stretch">
          {/* Invoice Header */}
          <Card>
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Box>
                  <HStack justify="space-between" align="start" mb={4}>
                    <Box>
                      <Badge colorScheme="blue" mb={2} fontSize={{ base: 'xs', md: 'sm' }}>
                        <FiFileText style={{ display: 'inline', marginRight: '4px' }} />
                        Invoice
                      </Badge>
                      <Heading size={{ base: 'md', md: 'lg' }}>
                        {invoice.title}
                      </Heading>
                      {invoice.description && (
                        <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }} mt={2}>
                          {invoice.description}
                        </Text>
                      )}
                    </Box>
                    <Badge colorScheme={invoice.status === 'paid' ? 'green' : 'orange'} fontSize="sm">
                      {invoice.status}
                    </Badge>
                  </HStack>

                  <Divider mb={4} />

                  {/* Invoice Details */}
                  <VStack spacing={2} align="stretch" fontSize={{ base: 'sm', md: 'md' }}>
                    <HStack justify="space-between">
                      <Text color="gray.600">Invoice Number:</Text>
                      <Text fontWeight="bold">{invoice.invoice_number}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">Issue Date:</Text>
                      <Text>{new Date(invoice.issue_date).toLocaleDateString()}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">Due Date:</Text>
                      <Text>{new Date(invoice.due_date).toLocaleDateString()}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">From:</Text>
                      <Text fontWeight="semibold">{invoice.merchant_name}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">To:</Text>
                      <Text fontWeight="semibold">{invoice.customer_name}</Text>
                    </HStack>
                  </VStack>
                </Box>
              </VStack>
            </CardBody>
          </Card>

          {/* Invoice Items */}
          {invoice.items && invoice.items.length > 0 && (
            <Card>
              <CardBody>
                <Heading size={{ base: 'sm', md: 'md' }} mb={4}>
                  Invoice Items
                </Heading>
                <TableContainer>
                  <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
                    <Thead>
                      <Tr>
                        <Th>Description</Th>
                        <Th isNumeric>Qty</Th>
                        <Th isNumeric>Price</Th>
                        <Th isNumeric>Amount</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {invoice.items.map((item: any, index: number) => (
                        <Tr key={index}>
                          <Td>{item.description}</Td>
                          <Td isNumeric>{parseFloat(item.quantity).toLocaleString()}</Td>
                          <Td isNumeric>
                            {currencySymbol}
                            {parseFloat(item.unit_price).toLocaleString('en-US', {
                              minimumFractionDigits: 2,
                              maximumFractionDigits: 2,
                            })}
                          </Td>
                          <Td isNumeric fontWeight="semibold">
                            {currencySymbol}
                            {parseFloat(item.amount).toLocaleString('en-US', {
                              minimumFractionDigits: 2,
                              maximumFractionDigits: 2,
                            })}
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </TableContainer>

                <Divider my={4} />

                {/* Totals */}
                <VStack spacing={2} align="stretch">
                  <HStack justify="space-between" fontSize={{ base: 'sm', md: 'md' }}>
                    <Text color="gray.600">Subtotal:</Text>
                    <Text>
                      {currencySymbol}
                      {parseFloat(invoice.subtotal).toLocaleString('en-US', {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2,
                      })}
                    </Text>
                  </HStack>
                  {invoice.tax_amount > 0 && (
                    <HStack justify="space-between" fontSize={{ base: 'sm', md: 'md' }}>
                      <Text color="gray.600">Tax:</Text>
                      <Text>
                        {currencySymbol}
                        {parseFloat(invoice.tax_amount).toLocaleString('en-US', {
                          minimumFractionDigits: 2,
                          maximumFractionDigits: 2,
                        })}
                      </Text>
                    </HStack>
                  )}
                  {invoice.discount_amount > 0 && (
                    <HStack justify="space-between" fontSize={{ base: 'sm', md: 'md' }}>
                      <Text color="gray.600">Discount:</Text>
                      <Text color="green.600">
                        -{currencySymbol}
                        {parseFloat(invoice.discount_amount).toLocaleString('en-US', {
                          minimumFractionDigits: 2,
                          maximumFractionDigits: 2,
                        })}
                      </Text>
                    </HStack>
                  )}
                  <Divider />
                  <HStack justify="space-between" fontSize={{ base: 'lg', md: 'xl' }}>
                    <Text fontWeight="bold">Total Amount:</Text>
                    <Text fontWeight="bold" color="brand.600">
                      {currencySymbol}
                      {parseFloat(invoice.total_amount).toLocaleString('en-US', {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2,
                      })}
                    </Text>
                  </HStack>
                  <Text fontSize="xs" color="gray.500">
                    + 1.5% processing fee will be applied
                  </Text>
                </VStack>
              </CardBody>
            </Card>
          )}

          {/* Notes */}
          {invoice.notes && (
            <Card>
              <CardBody>
                <Heading size={{ base: 'sm', md: 'md' }} mb={2}>
                  Notes
                </Heading>
                <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>
                  {invoice.notes}
                </Text>
              </CardBody>
            </Card>
          )}

          {/* Payment Form - Only show if invoice is unpaid */}
          {invoice.status !== 'paid' && (
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
                      Login to Pay Invoice
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
                                You don't have a wallet in {invoice?.currency?.code} currency. Please create one first.
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
                        Pay Invoice
                      </Button>
                    </VStack>
                  </form>
                )}
              </CardBody>
            </Card>
          )}

          {invoice.status === 'paid' && (
            <Alert status="success" borderRadius="md">
              <AlertIcon as={FiCheckCircle} />
              <Box>
                <AlertTitle fontSize={{ base: 'xs', md: 'sm' }}>Invoice Paid</AlertTitle>
                <AlertDescription fontSize="xs">
                  This invoice has already been paid. Thank you!
                </AlertDescription>
              </Box>
            </Alert>
          )}

          <Text fontSize="xs" color="gray.500" textAlign="center">
            Secured by PayCore • Payments are processed instantly
          </Text>
        </VStack>
      </Container>
    </Box>
  );
};
