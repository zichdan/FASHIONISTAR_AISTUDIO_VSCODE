import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  HStack,
  Stack,
  Card,
  CardBody,
  Button,
  Badge,
  Icon,
  SimpleGrid,
  useDisclosure,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  Select,
  useToast,
  Skeleton,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Image,
  Spinner,
} from '@chakra-ui/react';
import {
  FiZap,
  FiTv,
  FiWifi,
  FiPhone,
  FiDroplet,
  FiFileText,
  FiCheckCircle,
} from 'react-icons/fi';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import {
  useListProvidersQuery,
  useListPackagesQuery,
  useValidateCustomerMutation,
  usePayBillMutation,
  useListBillPaymentsQuery,
} from '@/features/bills/services/billsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { formatCurrency, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError } from '@/utils/errorHandlers';

interface PaymentForm {
  wallet_id: string;
  provider_id: string;
  package_id?: string;
  customer_id: string;
  amount?: number;
  pin: string;
}

const BILL_CATEGORIES = [
  { id: 'airtime', name: 'Airtime', icon: FiPhone, color: 'blue' },
  { id: 'data', name: 'Mobile Data', icon: FiWifi, color: 'purple' },
  { id: 'electricity', name: 'Electricity', icon: FiZap, color: 'yellow' },
  { id: 'cable_tv', name: 'Cable TV', icon: FiTv, color: 'red' },
  { id: 'water', name: 'Water', icon: FiDroplet, color: 'cyan' },
  { id: 'internet', name: 'Internet', icon: FiWifi, color: 'green' },
];

export const BillsPage = () => {
  const toast = useToast();

  // State
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<any>(null);
  const [selectedPackage, setSelectedPackage] = useState<any>(null);
  const [validatedCustomer, setValidatedCustomer] = useState<any>(null);

  // Modals
  const { isOpen: isPaymentOpen, onOpen: onPaymentOpen, onClose: onPaymentClose } = useDisclosure();
  const { isOpen: isHistoryOpen, onOpen: onHistoryOpen, onClose: onHistoryClose } = useDisclosure();

  // Forms
  const paymentForm = useForm<PaymentForm>();

  // API
  const { data: providersData, isLoading: loadingProviders, error: providersError } = useListProvidersQuery(
    { category: selectedCategory || undefined },
    { skip: !selectedCategory }
  );
  const { data: packagesData, isLoading: loadingPackages } = useListPackagesQuery(
    selectedProvider?.id || '',
    { skip: !selectedProvider }
  );
  const { data: walletsData, error: walletsError } = useListWalletsQuery();
  const { data: paymentsData, isLoading: loadingHistory } = useListBillPaymentsQuery({ limit: 20 });
  const [validateCustomer, { isLoading: validating }] = useValidateCustomerMutation();
  const [payBill, { isLoading: paying }] = usePayBillMutation();

  const providers = providersData?.data || [];
  const packages = packagesData?.data || [];
  const wallets = walletsData?.data || [];
  const payments = paymentsData?.data?.payments || [];

  // Handlers
  const handleCategorySelect = (categoryId: string) => {
    setSelectedCategory(categoryId);
    setSelectedProvider(null);
    setSelectedPackage(null);
    setValidatedCustomer(null);
  };

  const handleProviderSelect = (provider: any) => {
    setSelectedProvider(provider);
    setSelectedPackage(null);
    setValidatedCustomer(null);
    paymentForm.setValue('provider_id', provider.id);
    onPaymentOpen();
  };

  const handleValidateCustomer = async () => {
    const customerId = paymentForm.getValues('customer_id');

    if (!customerId) {
      toast({
        title: 'Please enter customer ID',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    if (!selectedProvider) {
      toast({
        title: 'Please select a provider first',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
      const result = await validateCustomer({
        provider_id: selectedProvider.provider_id || selectedProvider.id,
        customer_id: customerId,
      }).unwrap();
      setValidatedCustomer(result.data);
      toast({
        title: 'Customer validated',
        description: `Name: ${result.data?.customer_name}`,
        status: 'success',
        duration: 5000,
      });
    } catch (error: any) {
      toast({
        title: 'Validation failed',
        description: error.data?.message || 'Could not validate customer',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handlePayment = async (data: PaymentForm) => {
    if (!validatedCustomer) {
      toast({
        title: 'Please validate customer first',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    if (!selectedProvider) {
      toast({
        title: 'Provider not selected',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
      await payBill({
        wallet_id: data.wallet_id,
        provider_id: selectedProvider.provider_id || selectedProvider.id,
        customer_id: data.customer_id,
        package_id: data.package_id,
        amount: data.amount || selectedPackage?.price || 0,
        phone_number: data.customer_id, // For airtime/data
      }).unwrap();
      toast({
        title: 'Payment successful',
        description: 'Your bill has been paid',
        status: 'success',
        duration: 3000,
      });
      onPaymentClose();
      paymentForm.reset();
      setSelectedProvider(null);
      setSelectedPackage(null);
      setValidatedCustomer(null);
    } catch (error: any) {
      // Handle validation errors
      let errorMessage = error.data?.message || 'An error occurred';

      if (error.data?.data && typeof error.data.data === 'object') {
        // Format validation errors
        const validationErrors = Object.entries(error.data.data)
          .map(([field, msgs]: [string, any]) => {
            const messages = Array.isArray(msgs) ? msgs : [msgs];
            return `${field}: ${messages.join(', ')}`;
          })
          .join('\n');
        errorMessage = validationErrors || errorMessage;
      }

      toast({
        title: 'Payment failed',
        description: errorMessage,
        status: 'error',
        duration: 5000,
      });
    }
  };

  // Check for KYC errors
  if (walletsError && isKYCRequiredError(walletsError)) {
    return (
      <KYCRequired
        title="KYC Verification Required"
        description="To pay bills, you need to complete your KYC verification first."
      />
    );
  }

  if (providersError && isKYCRequiredError(providersError)) {
    return (
      <KYCRequired
        title="KYC Verification Required"
        description="To pay bills, you need to complete your KYC verification first."
      />
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Stack direction={{ base: "column", md: "row" }} justify="space-between" align={{ base: "stretch", md: "center" }} spacing={{ base: 4, md: 0 }}>
          <Box>
            <Heading size={{ base: "md", md: "lg" }} mb={2}>
              Pay Bills
            </Heading>
            <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Pay for airtime, data, electricity, and more</Text>
          </Box>
          <Button variant="outline" onClick={onHistoryOpen} size={{ base: "sm", md: "md" }} width={{ base: "full", md: "auto" }}>
            Payment History
          </Button>
        </Stack>

        {/* Categories Grid */}
        <Box>
          <Heading size={{ base: "sm", md: "md" }} mb={{ base: 3, md: 4 }}>
            Select Category
          </Heading>
          <SimpleGrid columns={{ base: 2, md: 3, lg: 6 }} spacing={4}>
            {BILL_CATEGORIES.map((category) => (
              <Card
                key={category.id}
                cursor="pointer"
                borderWidth={2}
                borderColor={selectedCategory === category.id ? `${category.color}.500` : 'transparent'}
                transition="all 0.2s"
                _hover={{ shadow: 'md', transform: 'translateY(-2px)' }}
                onClick={() => handleCategorySelect(category.id)}
              >
                <CardBody>
                  <VStack spacing={3}>
                    <Icon
                      as={category.icon}
                      boxSize={{ base: 8, md: 10 }}
                      color={`${category.color}.500`}
                    />
                    <Text fontWeight="600" fontSize={{ base: "xs", md: "sm" }} textAlign="center">
                      {category.name}
                    </Text>
                  </VStack>
                </CardBody>
              </Card>
            ))}
          </SimpleGrid>
        </Box>

        {/* Providers */}
        {selectedCategory && (
          <Box>
            <Heading size={{ base: "sm", md: "md" }} mb={{ base: 3, md: 4 }}>
              Select Provider
            </Heading>
            {loadingProviders ? (
              <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
                {[1, 2, 3, 4].map((i) => (
                  <Skeleton key={i} height="120px" borderRadius="lg" />
                ))}
              </SimpleGrid>
            ) : providers.length > 0 ? (
              <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
                {providers.map((provider: any) => (
                  <Card
                    key={provider.id}
                    cursor="pointer"
                    transition="all 0.2s"
                    _hover={{ shadow: 'lg', transform: 'translateY(-2px)' }}
                    onClick={() => handleProviderSelect(provider)}
                  >
                    <CardBody>
                      <VStack spacing={3}>
                        {provider.logo_url ? (
                          <Image
                            src={provider.logo_url}
                            alt={provider.name}
                            boxSize={{ base: "50px", md: "60px" }}
                            objectFit="contain"
                          />
                        ) : (
                          <Icon as={FiFileText} boxSize={{ base: 8, md: 10 }} color="gray.400" />
                        )}
                        <VStack spacing={1}>
                          <Text fontWeight="600" fontSize={{ base: "xs", md: "sm" }} textAlign="center">
                            {provider.name}
                          </Text>
                          {provider.available && (
                            <Badge colorScheme="green" fontSize={{ base: "2xs", md: "xs" }}>
                              Available
                            </Badge>
                          )}
                        </VStack>
                      </VStack>
                    </CardBody>
                  </Card>
                ))}
              </SimpleGrid>
            ) : (
              <EmptyState
                icon={FiFileText}
                title="No providers available"
                description="Check back later for available providers"
              />
            )}
          </Box>
        )}
      </VStack>

      {/* Payment Modal */}
      <Modal isOpen={isPaymentOpen} onClose={onPaymentClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={paymentForm.handleSubmit(handlePayment)}>
            <ModalHeader fontSize={{ base: "lg", md: "xl" }}>
              Pay {selectedProvider?.name} Bill
            </ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                {/* Select Package (if applicable) */}
                {selectedProvider?.has_packages && packages.length > 0 && (
                  <FormControl isRequired>
                    <FormLabel fontSize={{ base: "sm", md: "md" }}>Select Package</FormLabel>
                    <Select
                      {...paymentForm.register('package_id')}
                      placeholder="Choose package"
                      size={{ base: "sm", md: "md" }}
                      onChange={(e) => {
                        const pkg = packages.find((p: any) => p.id === e.target.value);
                        setSelectedPackage(pkg);
                      }}
                    >
                      {packages.map((pkg: any) => (
                        <option key={pkg.id} value={pkg.id}>
                          {pkg.name} - {formatCurrency(pkg.price, pkg.currency)}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                )}

                {/* Customer ID */}
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: "sm", md: "md" }}>
                    {selectedCategory === 'airtime' || selectedCategory === 'data'
                      ? 'Phone Number'
                      : selectedCategory === 'electricity'
                      ? 'Meter Number'
                      : selectedCategory === 'cable_tv'
                      ? 'Smart Card Number'
                      : 'Customer ID'}
                  </FormLabel>
                  <Stack direction={{ base: "column", sm: "row" }} spacing={2}>
                    <Input
                      {...paymentForm.register('customer_id')}
                      placeholder="Enter customer ID"
                      size={{ base: "sm", md: "md" }}
                    />
                    <Button onClick={handleValidateCustomer} isLoading={validating} size={{ base: "sm", md: "md" }} flexShrink={0}>
                      Validate
                    </Button>
                  </Stack>
                </FormControl>

                {/* Validated Customer Info */}
                {validatedCustomer && (
                  <Card bg="green.50" width="full">
                    <CardBody>
                      <HStack>
                        <Icon as={FiCheckCircle} color="green.500" boxSize={{ base: 5, md: 6 }} />
                        <VStack align="start" spacing={0} flex={1}>
                          <Text fontWeight="600" fontSize={{ base: "sm", md: "md" }}>{validatedCustomer.customer_name}</Text>
                          {validatedCustomer.address && (
                            <Text fontSize={{ base: "xs", md: "sm" }} color="gray.600">
                              {validatedCustomer.address}
                            </Text>
                          )}
                        </VStack>
                      </HStack>
                    </CardBody>
                  </Card>
                )}

                {/* Amount (if not package-based) */}
                {!selectedProvider?.has_packages && (
                  <FormControl isRequired>
                    <FormLabel fontSize={{ base: "sm", md: "md" }}>Amount</FormLabel>
                    <Input
                      type="number"
                      step="0.01"
                      {...paymentForm.register('amount', { valueAsNumber: true })}
                      placeholder="0.00"
                      size={{ base: "sm", md: "md" }}
                    />
                  </FormControl>
                )}

                {/* Wallet Selection */}
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: "sm", md: "md" }}>Payment Wallet</FormLabel>
                  <Select {...paymentForm.register('wallet_id')} placeholder="Select wallet" size={{ base: "sm", md: "md" }}>
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                {/* PIN */}
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: "sm", md: "md" }}>Wallet PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...paymentForm.register('pin')}
                    placeholder="Enter your PIN"
                    size={{ base: "sm", md: "md" }}
                  />
                </FormControl>

                {/* Payment Summary */}
                {(selectedPackage || paymentForm.watch('amount')) && (
                  <Card bg="gray.50" width="full">
                    <CardBody>
                      <VStack align="stretch" spacing={2}>
                        <HStack justify="space-between">
                          <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Amount</Text>
                          <Text fontWeight="bold" fontSize={{ base: "sm", md: "md" }}>
                            {formatCurrency(
                              selectedPackage?.price || paymentForm.watch('amount') || 0,
                              'NGN'
                            )}
                          </Text>
                        </HStack>
                        <HStack justify="space-between">
                          <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Fee</Text>
                          <Text fontWeight="bold" fontSize={{ base: "sm", md: "md" }}>
                            {formatCurrency(selectedProvider?.fee || 0, 'NGN')}
                          </Text>
                        </HStack>
                        <Box borderTop="1px" borderColor="gray.200" pt={2}>
                          <HStack justify="space-between">
                            <Text fontWeight="600" fontSize={{ base: "sm", md: "md" }}>Total</Text>
                            <Text fontWeight="bold" fontSize={{ base: "md", md: "lg" }}>
                              {formatCurrency(
                                (selectedPackage?.price || paymentForm.watch('amount') || 0) +
                                  (selectedProvider?.fee || 0),
                                'NGN'
                              )}
                            </Text>
                          </HStack>
                        </Box>
                      </VStack>
                    </CardBody>
                  </Card>
                )}
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onPaymentClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button
                colorScheme="brand"
                type="submit"
                isLoading={paying}
                isDisabled={!validatedCustomer}
                size={{ base: "sm", md: "md" }}
              >
                Pay Now
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Payment History Modal */}
      <Modal isOpen={isHistoryOpen} onClose={onHistoryClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader fontSize={{ base: "lg", md: "xl" }}>Payment History</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {loadingHistory ? (
              <LoadingSpinner />
            ) : payments.length > 0 ? (
              <Box overflowX="auto">
                <Table variant="simple" size={{ base: "sm", md: "md" }}>
                  <Thead>
                    <Tr>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Provider</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Customer ID</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Amount</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Status</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Date</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {payments.map((payment: any) => (
                      <Tr key={payment.payment_id}>
                        <Td fontSize={{ base: "xs", md: "sm" }}>{payment.provider?.name || 'N/A'}</Td>
                        <Td fontFamily="mono" fontSize={{ base: "xs", md: "sm" }}>
                          {payment.customer_id}
                        </Td>
                        <Td fontWeight="600" fontSize={{ base: "xs", md: "sm" }}>
                          {formatCurrency(payment.amount, payment.currency || 'NGN')}
                        </Td>
                        <Td>
                          <Badge colorScheme={getStatusColor(payment.status)} fontSize={{ base: "2xs", md: "xs" }}>
                            {payment.status}
                          </Badge>
                        </Td>
                        <Td fontSize={{ base: "xs", md: "sm" }} color="gray.600">
                          {formatRelativeTime(payment.created_at)}
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </Box>
            ) : (
              <EmptyState
                icon={FiFileText}
                title="No payment history"
                description="Your bill payments will appear here"
              />
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onHistoryClose} size={{ base: "sm", md: "md" }}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Container>
  );
};
