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
  Progress,
  Switch,
  Slider,
  SliderTrack,
  SliderFilledTrack,
  SliderThumb,
  NumberInput,
  NumberInputField,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Divider,
} from '@chakra-ui/react';
import {
  FiDollarSign,
  FiTrendingUp,
  FiCalendar,
  FiPercent,
  FiCheckCircle,
  FiClock,
  FiAlertCircle,
} from 'react-icons/fi';
import { useState, useEffect, useRef } from 'react';
import { useForm } from 'react-hook-form';
import {
  useListLoanProductsQuery,
  useCalculateLoanMutation,
  useCreateLoanApplicationMutation,
  useListLoanApplicationsQuery,
  useMakeRepaymentMutation,
  useGetRepaymentScheduleQuery,
  useEnableAutoRepaymentMutation,
  useDisableAutoRepaymentMutation,
  useGetAutoRepaymentSettingsQuery,
  useGetCreditScoreQuery,
  useGetLoanSummaryQuery,
} from '@/features/loans/services/loansApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { formatCurrency, formatDate, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError } from '@/utils/errorHandlers';

interface LoanApplicationForm {
  product_id: string;
  amount: number;
  tenure_months: number;
  repayment_frequency: string;
  purpose: string;
  wallet_id: string;
  collateral_type?: string;
  collateral_value?: number;
  guarantor_name?: string;
  guarantor_phone?: string;
  guarantor_email?: string;
}

interface RepaymentForm {
  loan_id: string;
  amount: number;
  wallet_id: string;
  pin: string;
}

interface AutoRepaymentForm {
  loan_id: string;
  wallet_id: string;
}

export const LoansPage = () => {
  const toast = useToast();

  // State
  const [selectedProduct, setSelectedProduct] = useState<any>(null);
  const [selectedLoan, setSelectedLoan] = useState<any>(null);
  const [calculatedLoan, setCalculatedLoan] = useState<any>(null);
  const [loanAmount, setLoanAmount] = useState(10000);
  const [loanTenure, setLoanTenure] = useState(3);
  const [repaymentFrequency, setRepaymentFrequency] = useState<string>('monthly');
  const [processingLoanId, setProcessingLoanId] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [processingStatus, setProcessingStatus] = useState<string>('');
  const pollingInterval = useRef<NodeJS.Timeout | null>(null);
  const notificationShown = useRef<boolean>(false);

  // Modals
  const { isOpen: isApplyOpen, onOpen: onApplyOpen, onClose: onApplyClose } = useDisclosure();
  const { isOpen: isCalculatorOpen, onOpen: onCalculatorOpen, onClose: onCalculatorClose } = useDisclosure();
  const { isOpen: isRepayOpen, onOpen: onRepayOpen, onClose: onRepayClose } = useDisclosure();
  const { isOpen: isScheduleOpen, onOpen: onScheduleOpen, onClose: onScheduleClose } = useDisclosure();
  const { isOpen: isAutoRepayOpen, onOpen: onAutoRepayOpen, onClose: onAutoRepayClose } = useDisclosure();
  const { isOpen: isDetailsOpen, onOpen: onDetailsOpen, onClose: onDetailsClose } = useDisclosure();

  // Forms
  const applyForm = useForm<LoanApplicationForm>();
  const repayForm = useForm<RepaymentForm>();
  const autoRepayForm = useForm<AutoRepaymentForm>();

  // API - Enable polling when processing a loan
  const { data: productsData, isLoading: loadingProducts, error: productsError } = useListLoanProductsQuery({});
  const { data: loansData, isLoading: loadingLoans, error: loansError } = useListLoanApplicationsQuery(undefined, {
    pollingInterval: processingLoanId ? 2000 : 0, // Poll every 2 seconds when processing
  });
  const { data: walletsData } = useListWalletsQuery();
  const { data: creditScoreData } = useGetCreditScoreQuery();
  const { data: summaryData } = useGetLoanSummaryQuery(undefined, {
    pollingInterval: processingLoanId ? 2000 : 0, // Poll summary too for updated balances
  });
  const [calculateLoan, { isLoading: calculating }] = useCalculateLoanMutation();
  const [createApplication, { isLoading: applying }] = useCreateLoanApplicationMutation();
  const [makeRepayment, { isLoading: repaying }] = useMakeRepaymentMutation();
  const [enableAutoRepay] = useEnableAutoRepaymentMutation();
  const [disableAutoRepay] = useDisableAutoRepaymentMutation();

  const products = productsData?.data || [];
  const loans = loansData?.data?.applications || [];
  const wallets = walletsData?.data || [];
  const creditScore = creditScoreData?.data;
  const summary = summaryData?.data;

  // Monitor loan processing status
  useEffect(() => {
    if (!processingLoanId) return;

    // Find the loan in the list
    const processingLoan = loans.find((loan: any) => loan.application_id === processingLoanId);

    if (processingLoan) {
      const status = processingLoan.status;

      // Update progress based on status
      if (status === 'pending') {
        // Gradually increase progress while pending
        if (processingProgress < 40) {
          const timer = setTimeout(() => {
            setProcessingProgress(prev => Math.min(prev + 5, 40));
          }, 1000);
          return () => clearTimeout(timer);
        }
        setProcessingStatus('Processing application...');
      } else if (status === 'approved') {
        setProcessingProgress(70);
        setProcessingStatus('Approved! Disbursing funds...');
      } else if (status === 'active' || status === 'disbursed') {
        setProcessingProgress(100);
        setProcessingStatus('Loan active! Funds disbursed.');

        // WebSocket notifications already handle loan approval/disbursement toasts
        // No need for duplicate frontend toast

        // Clear processing state after a delay
        setTimeout(() => {
          setProcessingLoanId(null);
          setProcessingProgress(0);
          setProcessingStatus('');
          notificationShown.current = false; // Reset for next time
        }, 3000);
      } else if (status === 'rejected') {
        setProcessingProgress(100);
        setProcessingStatus('Application rejected');

        // Show rejection notification only once
        if (!notificationShown.current) {
          notificationShown.current = true;
          toast({
            title: 'Application Rejected',
            description: processingLoan.rejection_reason || 'Your loan application was rejected.',
            status: 'error',
            duration: 8000,
            isClosable: true,
          });
        }

        setTimeout(() => {
          setProcessingLoanId(null);
          setProcessingProgress(0);
          setProcessingStatus('');
          notificationShown.current = false; // Reset for next time
        }, 3000);
      }
    }
  }, [loans, processingLoanId, processingProgress, toast]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollingInterval.current) {
        clearInterval(pollingInterval.current);
      }
    };
  }, []);

  // Handlers
  const handleCalculate = async () => {
    if (!selectedProduct) return;

    try {
      const result = await calculateLoan({
        product_id: selectedProduct.product_id || selectedProduct.id,
        amount: loanAmount,
        tenure_months: loanTenure,
        repayment_frequency: repaymentFrequency,
      }).unwrap();
      setCalculatedLoan(result.data);
      toast({
        title: 'Calculation complete',
        description: 'Loan details calculated successfully',
        status: 'success',
        duration: 3000,
      });
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
        title: 'Calculation failed',
        description: errorMessage,
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleApply = async (data: LoanApplicationForm) => {
    try {
      const result = await createApplication({
        loan_product_id: data.product_id,
        wallet_id: data.wallet_id,
        requested_amount: Number(data.amount),
        tenure_months: Number(data.tenure_months),
        repayment_frequency: data.repayment_frequency as any,
        purpose: data.purpose,
        collateral_type: data.collateral_type || 'none',
        collateral_value: Number(data.collateral_value) || 0,
        guarantor_name: data.guarantor_name || '',
        guarantor_phone: data.guarantor_phone || '',
        guarantor_email: data.guarantor_email || '',
      } as any).unwrap();

      const loanId = result.data?.application_id;

      // Start tracking the loan processing
      if (loanId) {
        notificationShown.current = false; // Reset notification flag
        setProcessingLoanId(loanId);
        setProcessingProgress(10);
        setProcessingStatus('pending');
      }

      toast({
        title: 'Application submitted',
        description: 'Your loan is being processed automatically',
        status: 'success',
        duration: 5000,
      });
      onApplyClose();
      applyForm.reset();
      setSelectedProduct(null);
    } catch (error: any) {
      let errorMessage = error.data?.message || 'An error occurred';

      if (error.data?.data && typeof error.data.data === 'object') {
        const validationErrors = Object.entries(error.data.data)
          .map(([field, msgs]: [string, any]) => {
            const messages = Array.isArray(msgs) ? msgs : [msgs];
            return `${field}: ${messages.join(', ')}`;
          })
          .join('\n');
        errorMessage = validationErrors || errorMessage;
      }

      toast({
        title: 'Application failed',
        description: errorMessage,
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleRepayment = async (data: RepaymentForm) => {
    try {
      await makeRepayment({
        ...data,
        amount: Number(data.amount),
      }).unwrap();
      toast({
        title: 'Repayment successful',
        status: 'success',
        duration: 3000,
      });
      onRepayClose();
      repayForm.reset();
      setSelectedLoan(null);
    } catch (error: any) {
      toast({
        title: 'Repayment failed',
        description: error.data?.message || 'An error occurred',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleToggleAutoRepay = async (loanId: string, enable: boolean, walletId?: string) => {
    try {
      if (enable && walletId) {
        await enableAutoRepay({ loan_id: loanId, wallet_id: walletId }).unwrap();
      } else {
        await disableAutoRepay(loanId).unwrap();
      }
      toast({
        title: `Auto-repayment ${enable ? 'enabled' : 'disabled'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to update auto-repayment',
        description: error.data?.message || 'An error occurred',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const openApplyModal = (product: any) => {
    setSelectedProduct(product);
    applyForm.setValue('product_id', product.product_id || product.id);
    applyForm.setValue('amount', Number(product.min_amount) || 0);
    applyForm.setValue('tenure_months', Number(product.min_tenure_months) || 1);
    applyForm.setValue('repayment_frequency', 'monthly');
    applyForm.setValue('collateral_type', 'savings');
    applyForm.setValue('collateral_value', Number(product.min_amount) || 1000);
    applyForm.setValue('guarantor_name', '');
    applyForm.setValue('guarantor_phone', '');
    applyForm.setValue('guarantor_email', '');
    onApplyOpen();
  };

  const openCalculatorModal = (product: any) => {
    setSelectedProduct(product);
    setLoanAmount(Number(product.min_amount) || 10000);
    setLoanTenure(Number(product.min_tenure_months) || 1);
    setCalculatedLoan(null);
    onCalculatorOpen();
  };

  const openRepayModal = (loan: any) => {
    setSelectedLoan(loan);
    repayForm.setValue('application_id', loan.application_id);
    onRepayOpen();
  };

  const openScheduleModal = (loan: any) => {
    setSelectedLoan(loan);
    onScheduleOpen();
  };

  const openDetailsModal = (loan: any) => {
    setSelectedLoan(loan);
    onDetailsOpen();
  };

  const error = productsError || loansError;

  if (error) {
    if (isKYCRequiredError(error)) {
      return (
        <KYCRequired
          title="KYC Verification Required"
          description="To manage your loans, you need to complete your KYC verification first."
        />
      );
    }

    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load loans. Please try again." />
      </Container>
    );
  }

  if (loadingProducts && loadingLoans) {
    return (
      <Container maxW="container.xl" py={8}>
        <VStack spacing={6} align="stretch">
          <Skeleton height="60px" />
          <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6}>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="200px" borderRadius="xl" />
            ))}
          </SimpleGrid>
        </VStack>
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Stack direction={{ base: 'column', md: 'row' }} justify="space-between" align={{ base: 'start', md: 'center' }} spacing={{ base: 2, md: 0 }}>
          <Box>
            <Heading size={{ base: 'md', md: 'lg' }} mb={2}>
              Loans
            </Heading>
            <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>Access quick loans and manage repayments</Text>
          </Box>
        </Stack>

        {/* Processing Progress Card */}
        {processingLoanId && (
          <Card bg="blue.50" borderColor="blue.200" borderWidth="2px">
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" align={{ base: 'start', sm: 'center' }} spacing={{ base: 2, sm: 0 }}>
                  <HStack spacing={2}>
                    <Icon as={FiClock} color="blue.600" boxSize={{ base: 4, md: 5 }} />
                    <Heading size={{ base: 'xs', md: 'sm' }} color="blue.800">
                      Processing Your Loan
                    </Heading>
                  </HStack>
                  <Badge colorScheme="blue" fontSize={{ base: 'xs', md: 'sm' }}>
                    {processingProgress}%
                  </Badge>
                </Stack>

                <Text fontSize={{ base: 'xs', md: 'sm' }} color="blue.700">
                  {processingStatus}
                </Text>

                <Progress
                  value={processingProgress}
                  size={{ base: 'md', md: 'lg' }}
                  colorScheme="blue"
                  hasStripe
                  isAnimated
                  borderRadius="md"
                />

                <Stack direction={{ base: 'column', sm: 'row' }} spacing={{ base: 2, sm: 4 }} fontSize={{ base: '2xs', md: 'xs' }} color="blue.600">
                  <HStack spacing={1}>
                    <Icon as={processingProgress >= 10 ? FiCheckCircle : FiClock} boxSize={{ base: 3, md: 4 }} />
                    <Text>Submitted</Text>
                  </HStack>
                  <HStack spacing={1}>
                    <Icon as={processingProgress >= 70 ? FiCheckCircle : FiClock} boxSize={{ base: 3, md: 4 }} />
                    <Text>Approved</Text>
                  </HStack>
                  <HStack spacing={1}>
                    <Icon as={processingProgress >= 100 ? FiCheckCircle : FiClock} boxSize={{ base: 3, md: 4 }} />
                    <Text>Disbursed</Text>
                  </HStack>
                </Stack>
              </VStack>
            </CardBody>
          </Card>
        )}

        {/* Summary Cards */}
        {summary && (
          <SimpleGrid columns={{ base: 1, sm: 2, md: 4 }} spacing={{ base: 4, md: 6 }}>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Active Loans</StatLabel>
                  <StatNumber fontSize={{ base: 'xl', md: '2xl' }}>{summary.active_loans}</StatNumber>
                  <StatHelpText fontSize={{ base: '2xs', md: 'xs' }}>
                    {formatCurrency(summary.outstanding_balance, 'NGN')} outstanding
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Total Borrowed</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }}>
                    {formatCurrency(summary.total_borrowed, 'NGN')}
                  </StatNumber>
                  <StatHelpText fontSize={{ base: '2xs', md: 'xs' }}>All time</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Total Repaid</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }}>
                    {formatCurrency(summary.total_repaid, 'NGN')}
                  </StatNumber>
                  <StatHelpText fontSize={{ base: '2xs', md: 'xs' }}>All time</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Credit Score</StatLabel>
                  <StatNumber fontSize={{ base: 'xl', md: '2xl' }} color={creditScore?.score >= 700 ? 'green.500' : 'orange.500'}>
                    {creditScore?.score || 'N/A'}
                  </StatNumber>
                  <StatHelpText fontSize={{ base: '2xs', md: 'xs' }}>{creditScore?.grade || 'Not rated'}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        <Tabs>
          <TabList>
            <Tab>Available Loans</Tab>
            <Tab>My Loans</Tab>
          </TabList>

          <TabPanels>
            {/* Available Loans */}
            <TabPanel px={0}>
              <VStack spacing={6} align="stretch">
                {loadingProducts ? (
                  <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
                    {[1, 2, 3].map((i) => (
                      <Skeleton key={i} height="250px" borderRadius="xl" />
                    ))}
                  </SimpleGrid>
                ) : products.length > 0 ? (
                  <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
                    {products.map((product: any) => (
                      <Card key={product.id} transition="all 0.2s" _hover={{ shadow: 'lg' }}>
                        <CardBody>
                          <VStack align="stretch" spacing={4}>
                            <HStack justify="space-between">
                              <Heading size={{ base: 'sm', md: 'md' }}>{product.name}</Heading>
                              <Icon as={FiDollarSign} boxSize={{ base: 5, md: 6 }} color="brand.500" />
                            </HStack>

                            <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600" noOfLines={2}>
                              {product.description}
                            </Text>

                            <VStack align="stretch" spacing={2}>
                              <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                                <Text color="gray.600">Amount Range</Text>
                                <Text fontWeight="600">
                                  {formatCurrency(product.min_amount, 'NGN')} -{' '}
                                  {formatCurrency(product.max_amount, 'NGN')}
                                </Text>
                              </HStack>
                              <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                                <Text color="gray.600">Interest Rate</Text>
                                <Text fontWeight="600" color="brand.500">
                                  {product.interest_rate}% p.a.
                                </Text>
                              </HStack>
                              <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                                <Text color="gray.600">Tenure</Text>
                                <Text fontWeight="600">
                                  {product.min_tenure_months} - {product.max_tenure_months} months
                                </Text>
                              </HStack>
                            </VStack>

                            <Stack direction={{ base: 'column', sm: 'row' }} spacing={2}>
                              <Button
                                size={{ base: 'xs', md: 'sm' }}
                                variant="outline"
                                flex={1}
                                onClick={() => openCalculatorModal(product)}
                              >
                                Calculate
                              </Button>
                              <Button
                                size={{ base: 'xs', md: 'sm' }}
                                colorScheme="brand"
                                flex={1}
                                onClick={() => openApplyModal(product)}
                              >
                                Apply Now
                              </Button>
                            </Stack>
                          </VStack>
                        </CardBody>
                      </Card>
                    ))}
                  </SimpleGrid>
                ) : (
                  <EmptyState
                    icon={FiDollarSign}
                    title="No loan products available"
                    description="Check back later for available loan products"
                  />
                )}
              </VStack>
            </TabPanel>

            {/* My Loans */}
            <TabPanel px={0}>
              {loadingLoans ? (
                <LoadingSpinner />
              ) : loans.length > 0 ? (
                <VStack spacing={4} align="stretch">
                  {loans.map((loan: any) => (
                    <Card key={loan.application_id}>
                      <CardBody>
                        <VStack align="stretch" spacing={4}>
                          <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" align={{ base: 'start', sm: 'center' }} spacing={{ base: 2, sm: 0 }}>
                            <VStack align="start" spacing={1}>
                              <Heading size={{ base: 'xs', md: 'sm' }}>{loan.loan_product_name}</Heading>
                              <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600">
                                ID: {loan.application_id.slice(0, 8)}...
                              </Text>
                            </VStack>
                            <Badge
                              colorScheme={getStatusColor(loan.status)}
                              fontSize={{ base: 'xs', md: 'sm' }}
                              px={3}
                              py={1}
                            >
                              {loan.status}
                            </Badge>
                          </Stack>

                          <SimpleGrid columns={{ base: 1, sm: 2, md: 4 }} spacing={4}>
                            <Box>
                              <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mb={1}>
                                Requested Amount
                              </Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>
                                {formatCurrency(loan.requested_amount, loan.currency?.code || 'NGN')}
                              </Text>
                            </Box>
                            <Box>
                              <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mb={1}>
                                {loan.approved_amount ? 'Approved Amount' : 'Total Repayable'}
                              </Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }} color={loan.approved_amount ? 'green.600' : 'gray.600'}>
                                {formatCurrency(loan.approved_amount || loan.total_repayable, loan.currency?.code || 'NGN')}
                              </Text>
                            </Box>
                            <Box>
                              <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mb={1}>
                                Monthly Payment
                              </Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>
                                {formatCurrency(loan.monthly_repayment, loan.currency?.code || 'NGN')}
                              </Text>
                            </Box>
                            <Box>
                              <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mb={1}>
                                Tenure
                              </Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>{loan.tenure_months} months</Text>
                            </Box>
                          </SimpleGrid>

                          <Box>
                            <HStack justify="space-between" mb={2}>
                              <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600">
                                Status
                              </Text>
                              <Text fontSize={{ base: 'xs', md: 'sm' }} fontWeight="600">
                                {loan.disbursed_at ? `Disbursed ${formatDate(loan.disbursed_at)}` : 'Pending Approval'}
                              </Text>
                            </HStack>
                            <Progress
                              value={loan.status === 'disbursed' || loan.status === 'active' ? 50 : loan.status === 'approved' ? 75 : 25}
                              colorScheme="brand"
                              borderRadius="full"
                            />
                          </Box>

                          <Stack direction={{ base: 'column', sm: 'row' }} spacing={2}>
                            {loan.status === 'active' && (
                              <>
                                <Button
                                  size={{ base: 'xs', md: 'sm' }}
                                  colorScheme="brand"
                                  onClick={() => openRepayModal(loan)}
                                >
                                  Make Payment
                                </Button>
                                <Button size={{ base: 'xs', md: 'sm' }} variant="outline" onClick={() => openScheduleModal(loan)}>
                                  View Schedule
                                </Button>
                              </>
                            )}
                            <Button size={{ base: 'xs', md: 'sm' }} variant="ghost" onClick={() => openDetailsModal(loan)}>
                              View Details
                            </Button>
                          </Stack>
                        </VStack>
                      </CardBody>
                    </Card>
                  ))}
                </VStack>
              ) : (
                <EmptyState
                  icon={FiDollarSign}
                  title="No active loans"
                  description="Apply for a loan to get started"
                />
              )}
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>

      {/* Loan Calculator Modal */}
      <Modal isOpen={isCalculatorOpen} onClose={onCalculatorClose} size={{ base: 'full', md: 'lg' }}>
        <ModalOverlay />
        <ModalContent mx={{ base: 0, md: 4 }}>
          <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Loan Calculator - {selectedProduct?.name}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={6} align="stretch">
              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Loan Amount: {formatCurrency(loanAmount, 'NGN')}</FormLabel>
                <Slider
                  aria-label="loan-amount-slider"
                  value={loanAmount}
                  onChange={(val) => setLoanAmount(val)}
                  min={Number(selectedProduct?.min_amount) || 1000}
                  max={Number(selectedProduct?.max_amount) || 1000000}
                  step={1000}
                  focusThumbOnChange={false}
                  colorScheme="brand"
                >
                  <SliderTrack>
                    <SliderFilledTrack />
                  </SliderTrack>
                  <SliderThumb boxSize={{ base: 4, md: 6 }} />
                </Slider>
                <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" mt={2} spacing={{ base: 1, sm: 0 }}>
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600">
                    Min: {formatCurrency(Number(selectedProduct?.min_amount) || 1000, 'NGN')}
                  </Text>
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600">
                    Max: {formatCurrency(Number(selectedProduct?.max_amount) || 1000000, 'NGN')}
                  </Text>
                </Stack>
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Tenure: {loanTenure} months</FormLabel>
                <Slider
                  aria-label="loan-tenure-slider"
                  value={loanTenure}
                  onChange={setLoanTenure}
                  min={Number(selectedProduct?.min_tenure_months) || 1}
                  max={Number(selectedProduct?.max_tenure_months) || 12}
                  step={1}
                  colorScheme="brand"
                >
                  <SliderTrack>
                    <SliderFilledTrack />
                  </SliderTrack>
                  <SliderThumb boxSize={{ base: 4, md: 6 }} />
                </Slider>
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Repayment Frequency</FormLabel>
                <Select
                  value={repaymentFrequency}
                  onChange={(e) => setRepaymentFrequency(e.target.value)}
                  fontSize={{ base: 'sm', md: 'md' }}
                >
                  <option value="weekly">Weekly</option>
                  <option value="bi_weekly">Bi-Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="quarterly">Quarterly</option>
                </Select>
              </FormControl>

              <Button onClick={handleCalculate} isLoading={calculating} colorScheme="brand" size={{ base: 'sm', md: 'md' }}>
                Calculate
              </Button>

              {calculatedLoan && (
                <Card bg="brand.50">
                  <CardBody>
                    <VStack align="stretch" spacing={3}>
                      <Heading size={{ base: 'xs', md: 'sm' }}>Loan Breakdown</Heading>
                      <HStack justify="space-between">
                        <Text color="gray.600" fontSize={{ base: 'xs', md: 'sm' }}>Principal</Text>
                        <Text fontWeight="600" fontSize={{ base: 'xs', md: 'sm' }}>
                          {formatCurrency(calculatedLoan.requested_amount || calculatedLoan.approved_amount, 'NGN')}
                        </Text>
                      </HStack>
                      <HStack justify="space-between">
                        <Text color="gray.600" fontSize={{ base: 'xs', md: 'sm' }}>Interest ({selectedProduct?.interest_rate}%)</Text>
                        <Text fontWeight="600" fontSize={{ base: 'xs', md: 'sm' }}>
                          {formatCurrency(calculatedLoan.total_interest, 'NGN')}
                        </Text>
                      </HStack>
                      <Divider />
                      <HStack justify="space-between">
                        <Text fontWeight="600" fontSize={{ base: 'xs', md: 'sm' }}>Total Repayment</Text>
                        <Text fontWeight="bold" fontSize={{ base: 'md', md: 'lg' }} color="brand.600">
                          {formatCurrency(calculatedLoan.total_repayable, 'NGN')}
                        </Text>
                      </HStack>
                      <HStack justify="space-between">
                        <Text fontWeight="600" fontSize={{ base: 'xs', md: 'sm' }}>Monthly Payment</Text>
                        <Text fontWeight="bold" fontSize={{ base: 'md', md: 'lg' }}>
                          {formatCurrency(calculatedLoan.monthly_repayment || calculatedLoan.installment_amount, 'NGN')}
                        </Text>
                      </HStack>
                    </VStack>
                  </CardBody>
                </Card>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Stack direction={{ base: 'column', sm: 'row' }} spacing={2} w={{ base: 'full', sm: 'auto' }}>
              <Button variant="ghost" onClick={onCalculatorClose} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                Close
              </Button>
              <Button colorScheme="brand" onClick={() => {
                onCalculatorClose();
                openApplyModal(selectedProduct);
              }} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                Apply for This Loan
              </Button>
            </Stack>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Apply for Loan Modal */}
      <Modal isOpen={isApplyOpen} onClose={onApplyClose} size={{ base: 'full', md: 'lg' }}>
        <ModalOverlay />
        <ModalContent mx={{ base: 0, md: 4 }}>
          <form onSubmit={applyForm.handleSubmit(handleApply)}>
            <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Apply for Loan</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Loan Amount</FormLabel>
                  <NumberInput
                    min={selectedProduct?.min_amount}
                    max={selectedProduct?.max_amount}
                    size={{ base: 'sm', md: 'md' }}
                  >
                    <NumberInputField
                      {...applyForm.register('amount', { valueAsNumber: true })}
                      placeholder="Enter amount"
                    />
                  </NumberInput>
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Min: {formatCurrency(selectedProduct?.min_amount, 'NGN')} | Max:{' '}
                    {formatCurrency(selectedProduct?.max_amount, 'NGN')}
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Tenure (Months)</FormLabel>
                  <NumberInput
                    min={selectedProduct?.min_tenure_months}
                    max={selectedProduct?.max_tenure_months}
                    size={{ base: 'sm', md: 'md' }}
                  >
                    <NumberInputField
                      {...applyForm.register('tenure_months', { valueAsNumber: true })}
                      placeholder="Enter tenure"
                    />
                  </NumberInput>
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Min: {selectedProduct?.min_tenure_months} | Max:{' '}
                    {selectedProduct?.max_tenure_months} months
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Repayment Frequency</FormLabel>
                  <Select {...applyForm.register('repayment_frequency')} placeholder="Select frequency" size={{ base: 'sm', md: 'md' }}>
                    <option value="weekly">Weekly</option>
                    <option value="bi_weekly">Bi-Weekly</option>
                    <option value="monthly">Monthly</option>
                    <option value="quarterly">Quarterly</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Collateral Type</FormLabel>
                  <Select {...applyForm.register('collateral_type')} placeholder="Select collateral" size={{ base: 'sm', md: 'md' }}>
                    <option value="none">No Collateral</option>
                    <option value="property">Property</option>
                    <option value="vehicle">Vehicle</option>
                    <option value="savings">Savings Account</option>
                    <option value="investment">Investment Portfolio</option>
                    <option value="other">Other</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Collateral Value</FormLabel>
                  <NumberInput min={0} size={{ base: 'sm', md: 'md' }}>
                    <NumberInputField
                      {...applyForm.register('collateral_value', { valueAsNumber: true })}
                      placeholder="Enter collateral value"
                    />
                  </NumberInput>
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Estimated value of collateral (set to 0 if no collateral)
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Guarantor Name</FormLabel>
                  <Input
                    {...applyForm.register('guarantor_name')}
                    placeholder="Enter guarantor's full name"
                    size={{ base: 'sm', md: 'md' }}
                  />
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Full name of your loan guarantor
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Guarantor Phone</FormLabel>
                  <Input
                    {...applyForm.register('guarantor_phone')}
                    placeholder="Enter guarantor's phone number"
                    type="tel"
                    size={{ base: 'sm', md: 'md' }}
                  />
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Valid phone number of your guarantor
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Guarantor Email</FormLabel>
                  <Input
                    {...applyForm.register('guarantor_email')}
                    placeholder="Enter guarantor's email address"
                    type="email"
                    size={{ base: 'sm', md: 'md' }}
                  />
                  <Text fontSize={{ base: '2xs', md: 'xs' }} color="gray.600" mt={1}>
                    Valid email address of your guarantor
                  </Text>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Purpose</FormLabel>
                  <Select {...applyForm.register('purpose')} placeholder="Select purpose" size={{ base: 'sm', md: 'md' }}>
                    <option value="business">Business</option>
                    <option value="personal">Personal</option>
                    <option value="education">Education</option>
                    <option value="medical">Medical</option>
                    <option value="emergency">Emergency</option>
                    <option value="other">Other</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Disbursement Wallet</FormLabel>
                  <Select {...applyForm.register('wallet_id')} placeholder="Select wallet" size={{ base: 'sm', md: 'md' }}>
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Stack direction={{ base: 'column', sm: 'row' }} spacing={2} w={{ base: 'full', sm: 'auto' }}>
                <Button variant="ghost" onClick={onApplyClose} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                  Cancel
                </Button>
                <Button colorScheme="brand" type="submit" isLoading={applying} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                  Submit Application
                </Button>
              </Stack>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Repayment Modal */}
      <Modal isOpen={isRepayOpen} onClose={onRepayClose} size={{ base: 'full', md: 'md' }}>
        <ModalOverlay />
        <ModalContent mx={{ base: 0, md: 4 }}>
          <form onSubmit={repayForm.handleSubmit(handleRepayment)}>
            <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Make Loan Repayment</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                {selectedLoan && (
                  <Card bg="gray.50" width="full">
                    <CardBody>
                      <VStack align="stretch" spacing={2}>
                        <HStack justify="space-between">
                          <Text color="gray.600" fontSize={{ base: 'xs', md: 'sm' }}>Outstanding Balance</Text>
                          <Text fontWeight="bold" color="red.600" fontSize={{ base: 'sm', md: 'md' }}>
                            {formatCurrency(selectedLoan.total_repayable || selectedLoan.approved_amount || selectedLoan.requested_amount, selectedLoan.currency?.code || 'NGN')}
                          </Text>
                        </HStack>
                        <HStack justify="space-between">
                          <Text color="gray.600" fontSize={{ base: 'xs', md: 'sm' }}>Next Payment Due</Text>
                          <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>
                            {formatCurrency(selectedLoan.monthly_repayment, selectedLoan.currency?.code || 'NGN')}
                          </Text>
                        </HStack>
                      </VStack>
                    </CardBody>
                  </Card>
                )}

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Payment Amount</FormLabel>
                  <NumberInput min={0} size={{ base: 'sm', md: 'md' }}>
                    <NumberInputField
                      {...repayForm.register('amount', { valueAsNumber: true })}
                      placeholder="Enter amount"
                    />
                  </NumberInput>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Payment Wallet</FormLabel>
                  <Select {...repayForm.register('wallet_id')} placeholder="Select wallet" size={{ base: 'sm', md: 'md' }}>
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Wallet PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...repayForm.register('pin')}
                    placeholder="Enter PIN"
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Stack direction={{ base: 'column', sm: 'row' }} spacing={2} w={{ base: 'full', sm: 'auto' }}>
                <Button variant="ghost" onClick={onRepayClose} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                  Cancel
                </Button>
                <Button colorScheme="brand" type="submit" isLoading={repaying} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>
                  Make Payment
                </Button>
              </Stack>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Repayment Schedule Modal */}
      <Modal isOpen={isScheduleOpen} onClose={onScheduleClose} size={{ base: 'full', md: 'xl' }}>
        <ModalOverlay />
        <ModalContent mx={{ base: 0, md: 4 }}>
          <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Repayment Schedule</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <RepaymentSchedule loanId={selectedLoan?.application_id} />
          </ModalBody>
          <ModalFooter>
            <Button onClick={onScheduleClose} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Loan Details Modal */}
      <Modal isOpen={isDetailsOpen} onClose={onDetailsClose} size={{ base: 'full', md: '2xl' }}>
        <ModalOverlay />
        <ModalContent mx={{ base: 0, md: 4 }}>
          <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Loan Details</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedLoan && (
              <VStack align="stretch" spacing={4}>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Loan Product</Text>
                  <Text fontWeight="600">{selectedLoan.product_name || 'N/A'}</Text>
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Requested Amount</Text>
                  <Text fontWeight="600" fontSize="lg">
                    {selectedLoan.currency?.symbol || ''}
                    {Number(selectedLoan.requested_amount || 0).toLocaleString()}
                  </Text>
                </Box>
                {selectedLoan.approved_amount && (
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>Approved Amount</Text>
                    <Text fontWeight="600" fontSize="lg" color="green.600">
                      {selectedLoan.currency?.symbol || ''}
                      {Number(selectedLoan.approved_amount).toLocaleString()}
                    </Text>
                  </Box>
                )}
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Interest Rate</Text>
                  <Text fontWeight="600">{selectedLoan.interest_rate}%</Text>
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Duration</Text>
                  <Text fontWeight="600">{selectedLoan.tenure_months} months</Text>
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Total Repayable</Text>
                  <Text fontWeight="600" fontSize="lg" color="brand.600">
                    {selectedLoan.currency?.symbol || ''}
                    {Number(selectedLoan.total_repayable || 0).toLocaleString()}
                  </Text>
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Monthly Payment</Text>
                  <Text fontWeight="600">
                    {selectedLoan.currency?.symbol || ''}
                    {Number(selectedLoan.monthly_repayment || 0).toLocaleString()}
                  </Text>
                </Box>
                {selectedLoan.outstanding_balance !== undefined && (
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>Outstanding Balance</Text>
                    <Text fontWeight="600">
                      {selectedLoan.currency?.symbol || ''}
                      {Number(selectedLoan.outstanding_balance || 0).toLocaleString()}
                    </Text>
                  </Box>
                )}
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Status</Text>
                  <Badge colorScheme={selectedLoan.status === 'active' ? 'green' : selectedLoan.status === 'completed' ? 'blue' : 'yellow'}>
                    {selectedLoan.status}
                  </Badge>
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.600" mb={1}>Application Date</Text>
                  <Text>{new Date(selectedLoan.created_at).toLocaleDateString()}</Text>
                </Box>
                {selectedLoan.disbursed_at && (
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>Disbursement Date</Text>
                    <Text>{new Date(selectedLoan.disbursed_at).toLocaleDateString()}</Text>
                  </Box>
                )}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onDetailsClose} size={{ base: 'sm', md: 'md' }} w={{ base: 'full', sm: 'auto' }}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Container>
  );
};

// Repayment Schedule Component
const RepaymentSchedule = ({ loanId }: { loanId: string }) => {
  const { data, isLoading } = useGetRepaymentScheduleQuery(loanId, { skip: !loanId });
  const schedule = data?.data || [];

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (schedule.length === 0) {
    return <EmptyState icon={FiCalendar} title="No schedule available" />;
  }

  return (
    <Box overflowX="auto">
      <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
        <Thead>
          <Tr>
            <Th fontSize={{ base: 'xs', md: 'sm' }}>Period</Th>
            <Th fontSize={{ base: 'xs', md: 'sm' }}>Due Date</Th>
            <Th isNumeric fontSize={{ base: 'xs', md: 'sm' }}>Amount</Th>
            <Th fontSize={{ base: 'xs', md: 'sm' }}>Status</Th>
          </Tr>
        </Thead>
        <Tbody>
          {schedule.map((item: any, index: number) => (
            <Tr key={item.schedule_id}>
              <Td fontSize={{ base: 'xs', md: 'sm' }}>{item.installment_number}</Td>
              <Td fontSize={{ base: 'xs', md: 'sm' }}>{formatDate(item.due_date)}</Td>
              <Td isNumeric fontWeight="600" fontSize={{ base: 'xs', md: 'sm' }}>
                {formatCurrency(item.total_amount, 'NGN')}
              </Td>
              <Td>
                <Badge colorScheme={getStatusColor(item.status)} fontSize={{ base: '2xs', md: 'xs' }}>{item.status}</Badge>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </Box>
  );
};
