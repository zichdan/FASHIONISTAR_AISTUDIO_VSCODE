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
  InputGroup,
  InputLeftElement,
  Textarea,
  NumberInput,
  NumberInputField,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Checkbox,
  Divider,
} from '@chakra-ui/react';
import {
  FiSend,
  FiDownload,
  FiUpload,
  FiSearch,
  FiFilter,
  FiArrowUpRight,
  FiArrowDownRight,
  FiAlertCircle,
  FiRefreshCw,
} from 'react-icons/fi';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import {
  useListTransactionsQuery,
  useTransferMutation,
  useInitiateDepositMutation,
  useInitiateWithdrawalMutation,
  useVerifyBankAccountMutation,
  useGetWithdrawalBanksQuery,
  useCreateDisputeMutation,
  useGetTransactionStatisticsQuery,
} from '@/features/transactions/services/transactionsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { formatCurrency, formatDateTime, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError, getErrorMessage } from '@/utils/errorHandlers';
import { useWebSocket } from '@/hooks/useWebSocket';

interface TransferForm {
  wallet_id: string;
  recipient_wallet_id?: string;
  recipient_email?: string;
  amount: number;
  description: string;
  pin?: string;
  use_biometric?: boolean;
}

interface DepositForm {
  wallet_id: string;
  amount: number;
  payment_method: string;
}

interface WithdrawalForm {
  wallet_id: string;
  amount: number;
  account_number: string;
  bank_code: string;
  account_name?: string;
  pin: string;
}

interface DisputeForm {
  dispute_type: string;
  reason: string;
}

export const TransactionsPage = () => {
  const toast = useToast();

  // WebSocket for real-time updates
  const { latestNotification } = useWebSocket();

  // State
  const [selectedTransaction, setSelectedTransaction] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterType, setFilterType] = useState('');
  const [page, setPage] = useState(1);
  const [verifiedAccount, setVerifiedAccount] = useState<any>(null);
  const [useBiometric, setUseBiometric] = useState(false);

  // Modals
  const { isOpen: isTransferOpen, onOpen: onTransferOpen, onClose: onTransferClose } = useDisclosure();
  const { isOpen: isDepositOpen, onOpen: onDepositOpen, onClose: onDepositClose } = useDisclosure();
  const { isOpen: isWithdrawOpen, onOpen: onWithdrawOpen, onClose: onWithdrawClose } = useDisclosure();
  const { isOpen: isDisputeOpen, onOpen: onDisputeOpen, onClose: onDisputeClose } = useDisclosure();
  const { isOpen: isDetailsOpen, onOpen: onDetailsOpen, onClose: onDetailsClose } = useDisclosure();

  // Forms
  const transferForm = useForm<TransferForm>();
  const depositForm = useForm<DepositForm>();
  const withdrawForm = useForm<WithdrawalForm>();
  const disputeForm = useForm<DisputeForm>();

  // API
  const { data: transactionsData, isLoading, error, refetch } = useListTransactionsQuery({
    page,
    limit: 10,
    ...(filterStatus && { status: filterStatus }),
    ...(filterType && { transaction_type: filterType }),
    ...(searchQuery && { search: searchQuery }),
  });
  const { data: walletsData, refetch: refetchWallets } = useListWalletsQuery();
  const { data: banksData } = useGetWithdrawalBanksQuery();
  const { data: statsData, refetch: refetchStats } = useGetTransactionStatisticsQuery({});
  const [transfer, { isLoading: transferring }] = useTransferMutation();
  const [initiateDeposit, { isLoading: depositing }] = useInitiateDepositMutation();
  const [initiateWithdrawal, { isLoading: withdrawing }] = useInitiateWithdrawalMutation();
  const [verifyBankAccount, { isLoading: verifying }] = useVerifyBankAccountMutation();
  const [createDispute, { isLoading: disputing }] = useCreateDisputeMutation();

  const transactions = transactionsData?.data?.transactions || [];
  const pagination = transactionsData?.data ? {
    total: transactionsData.data.total,
    limit: transactionsData.data.limit,
    page: transactionsData.data.page,
    total_pages: transactionsData.data.total_pages,
  } : undefined;
  const wallets = walletsData?.data || [];
  const banks = banksData?.data?.banks || [];
  const stats = statsData?.data;

  // Listen for transaction-related WebSocket notifications
  useEffect(() => {
    if (latestNotification) {
      // Check if this is a transaction-related notification based on notification_type or related_object_type
      const transactionTypes = ['transfer', 'payment', 'wallet'];
      const transactionRelatedTypes = ['Transaction', 'Deposit', 'Withdrawal', 'Transfer'];

      const isTransactionRelated =
        transactionTypes.includes(latestNotification.notification_type) ||
        (latestNotification.related_object_type && transactionRelatedTypes.includes(latestNotification.related_object_type));

      if (isTransactionRelated) {
        // Refresh transactions list, wallets, and stats
        refetch();
        refetchWallets();
        refetchStats();
      }
    }
  }, [latestNotification, refetch, refetchWallets, refetchStats]);

  // Biometric authentication helper
  const authenticateWithBiometric = async (): Promise<{ biometric_token: string; device_id: string } | null> => {
    try {
      // Check if WebAuthn is supported
      if (!window.PublicKeyCredential) {
        toast({
          title: 'Biometric not supported',
          description: 'Your device does not support biometric authentication',
          status: 'error',
          duration: 5000,
        });
        return null;
      }

      // Check if user has already enrolled biometrics
      const storedToken = localStorage.getItem('biometric_trust_token');
      const storedDeviceId = localStorage.getItem('biometric_device_id');

      if (storedToken && storedDeviceId) {
        // User already has a trust token, just prompt for Touch ID to confirm
        try {
          // Create a challenge to trigger Touch ID prompt
          const challenge = new Uint8Array(32);
          crypto.getRandomValues(challenge);

          const userId = new Uint8Array(16);
          crypto.getRandomValues(userId);

          // This will prompt for Touch ID
          await navigator.credentials.create({
            publicKey: {
              challenge,
              rp: {
                name: "PayCore",
                id: window.location.hostname,
              },
              user: {
                id: userId,
                name: "user@paycore.com",
                displayName: "PayCore User",
              },
              pubKeyCredParams: [
                { type: "public-key", alg: -7 },  // ES256
                { type: "public-key", alg: -257 }, // RS256
              ],
              authenticatorSelection: {
                authenticatorAttachment: "platform",
                userVerification: "required",
              },
              timeout: 60000,
            },
          });

          // Touch ID succeeded, return the stored token
          return { biometric_token: storedToken, device_id: storedDeviceId };
        } catch (error: any) {
          if (error.name === 'NotAllowedError') {
            toast({
              title: 'Authentication cancelled',
              description: 'Touch ID authentication was cancelled',
              status: 'warning',
              duration: 3000,
            });
          }
          return null;
        }
      }

      // First time enrollment - need to register with backend
      toast({
        title: 'Biometric enrollment required',
        description: 'Please wait while we enroll your biometrics...',
        status: 'info',
        duration: 3000,
      });

      // Generate device ID
      const device_id = `device_${Date.now()}_${Math.random().toString(36).substring(7)}`;

      // Call backend to enable biometrics and get trust token
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
      const response = await fetch(`${API_BASE_URL}/auth/biometrics/enable`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
        },
        credentials: 'include',
        body: JSON.stringify({ device_id }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to enable biometrics');
      }

      const data = await response.json();
      const trust_token = data.data.trust_token;

      // Store the trust token
      localStorage.setItem('biometric_trust_token', trust_token);
      localStorage.setItem('biometric_device_id', device_id);

      toast({
        title: 'Biometric enrolled',
        description: 'You can now use biometrics for authentication',
        status: 'success',
        duration: 3000,
      });

      return { biometric_token: trust_token, device_id };
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        toast({
          title: 'Authentication cancelled',
          description: 'Touch ID authentication was cancelled',
          status: 'warning',
          duration: 3000,
        });
      } else if (error.name === 'NotSupportedError') {
        toast({
          title: 'Touch ID not available',
          description: 'Touch ID is not configured on this device. Please use PIN instead.',
          status: 'error',
          duration: 5000,
        });
      } else {
        toast({
          title: 'Authentication failed',
          description: error.message || 'Failed to authenticate with Touch ID',
          status: 'error',
          duration: 5000,
        });
      }
      return null;
    }
  };

  // Handlers
  const handleTransfer = async (data: TransferForm) => {
    try {
      let biometric_token: string | undefined;
      let device_id: string | undefined;

      // If biometric is selected, authenticate
      if (useBiometric) {
        const biometricResult = await authenticateWithBiometric();
        if (!biometricResult) {
          // Authentication failed or was cancelled
          return;
        }
        biometric_token = biometricResult.biometric_token;
        device_id = biometricResult.device_id;
      }

      await transfer({
        from_wallet_id: data.wallet_id,
        to_wallet_id: data.recipient_wallet_id!,
        amount: Number(data.amount),
        description: data.description,
        pin: useBiometric ? undefined : data.pin,
        biometric_token,
        device_id,
      }).unwrap();
      toast({
        title: 'Transfer successful',
        status: 'success',
        duration: 3000,
      });
      onTransferClose();
      transferForm.reset();
      setUseBiometric(false);
      refetch();
    } catch (error: any) {
      toast({
        title: 'Transfer failed',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleDeposit = async (data: DepositForm) => {
    try {
      const result = await initiateDeposit({
        ...data,
        amount: Number(data.amount),
      }).unwrap();

      toast({
        title: 'Deposit initiated',
        description: result.data?.payment_url
          ? 'Complete the payment to fund your wallet'
          : 'Deposit processing... You will be notified when complete.',
        status: 'success',
        duration: 5000,
      });

      // Redirect to payment gateway if needed
      if (result.data?.payment_url) {
        window.open(result.data.payment_url, '_blank');
      }

      onDepositClose();
      depositForm.reset();
    } catch (error: any) {
      toast({
        title: 'Deposit failed',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };


  const handleVerifyAccount = async () => {
    // Use watch to get the latest form values
    const formValues = withdrawForm.getValues();
    const accountNumber = formValues.account_number;
    const bankCode = formValues.bank_code;

    console.log('Form values:', { accountNumber, bankCode, allValues: formValues });

    if (!accountNumber || !bankCode) {
      toast({
        title: 'Please enter account number and select bank',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
      const payload = {
        account_number: accountNumber.trim(),
        bank_code: bankCode.trim(),
      };

      console.log('Sending payload:', payload);

      const result = await verifyBankAccount(payload).unwrap();
      setVerifiedAccount(result.data);
      withdrawForm.setValue('account_name', result.data?.account_name);
      toast({
        title: 'Account verified',
        description: `Account Name: ${result.data?.account_name}`,
        status: 'success',
        duration: 5000,
      });
    } catch (error: any) {
      console.error('Verification error:', error);
      toast({
        title: 'Verification failed',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleWithdraw = async (data: WithdrawalForm) => {
    if (!verifiedAccount) {
      toast({
        title: 'Please verify the account first',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
      await initiateWithdrawal({
        wallet_id: data.wallet_id,
        amount: Number(data.amount),
        destination: 'bank_account',
        account_details: {
          account_number: data.account_number,
          account_name: data.account_name || verifiedAccount.account_name,
          bank_code: data.bank_code,
          bank_name: verifiedAccount.bank_name,
        },
        pin: data.pin ? Number(data.pin) : undefined,
      }).unwrap();
      toast({
        title: 'Withdrawal initiated',
        description: 'Your funds will be sent shortly',
        status: 'success',
        duration: 3000,
      });
      onWithdrawClose();
      withdrawForm.reset();
      setVerifiedAccount(null);
      refetch();
    } catch (error: any) {
      toast({
        title: 'Withdrawal failed',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleDispute = async (data: DisputeForm) => {
    if (!selectedTransaction?.transaction_id) {
      toast({
        title: 'Error',
        description: 'No transaction selected',
        status: 'error',
        duration: 5000,
      });
      return;
    }

    try {
      await createDispute({
        transactionId: selectedTransaction.transaction_id,
        data: {
          dispute_type: data.dispute_type,
          reason: data.reason,
        },
      }).unwrap();
      toast({
        title: 'Dispute created',
        description: 'We will review your dispute and get back to you',
        status: 'success',
        duration: 5000,
      });
      onDisputeClose();
      disputeForm.reset();
      setSelectedTransaction(null);
    } catch (error: any) {
      toast({
        title: 'Failed to create dispute',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const openDetailsModal = (transaction: any) => {
    setSelectedTransaction(transaction);
    onDetailsOpen();
  };

  const openDisputeModal = (transaction: any) => {
    setSelectedTransaction(transaction);
    disputeForm.setValue('transaction_id', transaction.id);
    onDisputeOpen();
  };

  if (isLoading && !transactions.length) {
    return (
      <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
        <VStack spacing={6} align="stretch">
          <Skeleton height="60px" />
          <Skeleton height="400px" />
        </VStack>
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Stack direction={{ base: "column", md: "row" }} justify="space-between" spacing={{ base: 4, md: 0 }}>
          <Box>
            <Heading size={{ base: "md", md: "lg" }} mb={2}>
              Transactions
            </Heading>
            <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>View and manage your transaction history</Text>
          </Box>
          <Stack direction={{ base: "column", sm: "row" }} spacing={{ base: 2, sm: 3 }}>
            <Button
              leftIcon={<Icon as={FiDownload} />}
              colorScheme="green"
              onClick={onDepositOpen}
              size={{ base: "sm", md: "md" }}
            >
              Add Money
            </Button>
            <Button
              leftIcon={<Icon as={FiUpload} />}
              variant="outline"
              onClick={onWithdrawOpen}
              size={{ base: "sm", md: "md" }}
            >
              Withdraw
            </Button>
            <Button
              leftIcon={<Icon as={FiSend} />}
              colorScheme="brand"
              onClick={onTransferOpen}
              size={{ base: "sm", md: "md" }}
            >
              Transfer
            </Button>
          </Stack>
        </Stack>

        {/* Statistics */}
        {stats && (
          <SimpleGrid columns={{ base: 1, md: 4 }} spacing={6}>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>Total Transactions</StatLabel>
                  <StatNumber>{stats.total_transactions}</StatNumber>
                  <StatHelpText>All time</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>Total Volume</StatLabel>
                  <StatNumber fontSize="xl">
                    {formatCurrency(
                      (parseFloat(stats.total_sent || '0') + parseFloat(stats.total_received || '0')),
                      'NGN'
                    )}
                  </StatNumber>
                  <StatHelpText>All time</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>Money In</StatLabel>
                  <StatNumber fontSize="xl" color="green.600">
                    {formatCurrency(parseFloat(stats.total_received || '0'), 'NGN')}
                  </StatNumber>
                  <StatHelpText>Credits</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>Money Out</StatLabel>
                  <StatNumber fontSize="xl" color="red.600">
                    {formatCurrency(parseFloat(stats.total_sent || '0'), 'NGN')}
                  </StatNumber>
                  <StatHelpText>Debits</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        {/* Filters */}
        <Card>
          <CardBody>
            <Stack direction={{ base: "column", md: "row" }} spacing={4}>
              <InputGroup maxW={{ base: "full", md: "300px" }}>
                <InputLeftElement>
                  <Icon as={FiSearch} color="gray.400" />
                </InputLeftElement>
                <Input
                  placeholder="Search transactions..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  size={{ base: "sm", md: "md" }}
                />
              </InputGroup>

              <Select
                maxW={{ base: "full", md: "200px" }}
                placeholder="All Status"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                size={{ base: "sm", md: "md" }}
              >
                <option value="completed">Completed</option>
                <option value="pending">Pending</option>
                <option value="failed">Failed</option>
              </Select>

              <Select
                maxW={{ base: "full", md: "200px" }}
                placeholder="All Types"
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                size={{ base: "sm", md: "md" }}
              >
                <option value="transfer">Transfer</option>
                <option value="deposit">Deposit</option>
                <option value="withdrawal">Withdrawal</option>
                <option value="bill_payment">Bill Payment</option>
              </Select>

              <Button
                leftIcon={<Icon as={FiRefreshCw} />}
                variant="ghost"
                onClick={() => {
                  setSearchQuery('');
                  setFilterStatus('');
                  setFilterType('');
                  refetch();
                }}
                size={{ base: "sm", md: "md" }}
              >
                Reset
              </Button>
            </Stack>
          </CardBody>
        </Card>

        {/* Transactions Table */}
        {error && isKYCRequiredError(error) ? (
          <KYCRequired
            title="KYC Verification Required"
            description="To view your transactions, you need to complete your KYC verification first."
          />
        ) : (
        <Card>
          <CardBody>
            {error ? (
              <ErrorAlert message="Failed to load transactions. Please try again." />
            ) : transactions.length > 0 ? (
              <>
                <Box overflowX="auto">
                  <Table variant="simple" size={{ base: "sm", md: "md" }}>
                    <Thead>
                      <Tr>
                        <Th fontSize={{ base: "xs", md: "sm" }}>Type</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }}>Reference</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }} display={{ base: "none", sm: "table-cell" }}>Description</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }}>Amount</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }}>Status</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }} display={{ base: "none", md: "table-cell" }}>Date</Th>
                        <Th fontSize={{ base: "xs", md: "sm" }}>Actions</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {transactions.map((transaction: any) => (
                        <Tr key={transaction.id}>
                          <Td fontSize={{ base: "xs", md: "sm" }}>
                            <HStack spacing={{ base: 1, md: 2 }}>
                              <Icon
                                as={transaction.type === 'credit' ? FiArrowDownRight : FiArrowUpRight}
                                color={transaction.type === 'credit' ? 'green.500' : 'red.500'}
                                boxSize={{ base: 3, md: 4 }}
                              />
                              <Text textTransform="capitalize" display={{ base: "none", sm: "block" }}>
                                {transaction.transaction_type.replace('_', ' ')}
                              </Text>
                            </HStack>
                          </Td>
                          <Td fontFamily="mono" fontSize={{ base: "xs", md: "sm" }}>
                            {transaction.reference}
                          </Td>
                          <Td maxW="200px" isTruncated fontSize={{ base: "xs", md: "sm" }} display={{ base: "none", sm: "table-cell" }}>
                            {transaction.description || '-'}
                          </Td>
                          <Td fontWeight="600" fontSize={{ base: "xs", md: "sm" }}>
                            <Text color={transaction.type === 'credit' ? 'green.600' : 'red.600'}>
                              {transaction.type === 'credit' ? '+' : '-'}
                              {formatCurrency(transaction.amount, transaction.currency)}
                            </Text>
                          </Td>
                          <Td fontSize={{ base: "xs", md: "sm" }}>
                            <Badge colorScheme={getStatusColor(transaction.status)} fontSize={{ base: "2xs", md: "xs" }}>
                              {transaction.status}
                            </Badge>
                          </Td>
                          <Td fontSize={{ base: "xs", md: "sm" }} color="gray.600" display={{ base: "none", md: "table-cell" }}>
                            {formatRelativeTime(transaction.completed_at || transaction.initiated_at)}
                          </Td>
                          <Td fontSize={{ base: "xs", md: "sm" }}>
                            <Stack direction={{ base: "column", sm: "row" }} spacing={{ base: 1, sm: 2 }}>
                              <Button
                                size={{ base: "xs", md: "sm" }}
                                variant="ghost"
                                onClick={() => openDetailsModal(transaction)}
                              >
                                View
                              </Button>
                              {transaction.status === 'completed' && (
                                <Button
                                  size={{ base: "xs", md: "sm" }}
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => openDisputeModal(transaction)}
                                  display={{ base: "none", sm: "inline-flex" }}
                                >
                                  Dispute
                                </Button>
                              )}
                            </Stack>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </Box>

                {/* Pagination */}
                {pagination && pagination.total_pages > 1 && (
                  <HStack justify="center" mt={6} spacing={1} flexWrap="wrap">
                    <Button
                      size={{ base: "xs", md: "sm" }}
                      onClick={() => setPage(page - 1)}
                      isDisabled={page === 1}
                      variant="ghost"
                    >
                      Previous
                    </Button>

                    {/* First page */}
                    {page > 3 && (
                      <>
                        <Button
                          size={{ base: "xs", md: "sm" }}
                          onClick={() => setPage(1)}
                          variant="ghost"
                        >
                          1
                        </Button>
                        {page > 4 && (
                          <Text px={2} color="gray.500" fontSize={{ base: "xs", md: "sm" }}>...</Text>
                        )}
                      </>
                    )}

                    {/* Page numbers around current page */}
                    {Array.from({ length: pagination.total_pages }, (_, i) => i + 1)
                      .filter(pageNum => {
                        // Show current page and 2 pages on each side
                        return pageNum >= page - 2 && pageNum <= page + 2;
                      })
                      .map(pageNum => (
                        <Button
                          key={pageNum}
                          size={{ base: "xs", md: "sm" }}
                          onClick={() => setPage(pageNum)}
                          colorScheme={pageNum === page ? "brand" : "gray"}
                          variant={pageNum === page ? "solid" : "ghost"}
                        >
                          {pageNum}
                        </Button>
                      ))}

                    {/* Last page */}
                    {page < pagination.total_pages - 2 && (
                      <>
                        {page < pagination.total_pages - 3 && (
                          <Text px={2} color="gray.500" fontSize={{ base: "xs", md: "sm" }}>...</Text>
                        )}
                        <Button
                          size={{ base: "xs", md: "sm" }}
                          onClick={() => setPage(pagination.total_pages)}
                          variant="ghost"
                        >
                          {pagination.total_pages}
                        </Button>
                      </>
                    )}

                    <Button
                      size={{ base: "xs", md: "sm" }}
                      onClick={() => setPage(page + 1)}
                      isDisabled={page === pagination.total_pages}
                      variant="ghost"
                    >
                      Next
                    </Button>
                  </HStack>
                )}
              </>
            ) : (
              <EmptyState
                icon={FiSend}
                title="No transactions yet"
                description="Your transaction history will appear here"
              />
            )}
          </CardBody>
        </Card>
        )}
      </VStack>

      {/* Transfer Modal */}
      <Modal isOpen={isTransferOpen} onClose={onTransferClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={transferForm.handleSubmit(handleTransfer)}>
            <ModalHeader>Send Money</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>From Wallet</FormLabel>
                  <Select {...transferForm.register('wallet_id')} placeholder="Select wallet">
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Recipient Wallet ID</FormLabel>
                  <Input
                    {...transferForm.register('recipient_wallet_id')}
                    placeholder="Enter recipient wallet ID"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Amount</FormLabel>
                  <NumberInput min={0}>
                    <NumberInputField
                      {...transferForm.register('amount', { valueAsNumber: true })}
                      placeholder="0.00"
                    />
                  </NumberInput>
                </FormControl>

                <FormControl>
                  <FormLabel>Description (Optional)</FormLabel>
                  <Input {...transferForm.register('description')} placeholder="What's this for?" />
                </FormControl>

                <Divider />

                <Checkbox
                  isChecked={useBiometric}
                  onChange={(e) => setUseBiometric(e.target.checked)}
                  colorScheme="brand"
                >
                  Use biometric authentication (fingerprint/face ID)
                </Checkbox>

                {!useBiometric && (
                  <FormControl isRequired>
                    <FormLabel>Wallet PIN</FormLabel>
                    <Input
                      type="password"
                      maxLength={4}
                      {...transferForm.register('pin')}
                      placeholder="Enter your 4-digit PIN"
                    />
                  </FormControl>
                )}

                {useBiometric && (
                  <Alert status="info" borderRadius="md">
                    <AlertIcon />
                    <Box>
                      <AlertTitle fontSize="sm">Biometric Authentication</AlertTitle>
                      <AlertDescription fontSize="sm">
                        You'll be prompted to authenticate with your fingerprint or face ID when you submit.
                      </AlertDescription>
                    </Box>
                  </Alert>
                )}
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onTransferClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={transferring} size={{ base: "sm", md: "md" }}>
                Send Money
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Deposit Modal */}
      <Modal isOpen={isDepositOpen} onClose={onDepositClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={depositForm.handleSubmit(handleDeposit)}>
            <ModalHeader>Add Money</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>To Wallet</FormLabel>
                  <Select {...depositForm.register('wallet_id')} placeholder="Select wallet">
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} ({wallet.currency?.code || 'NGN'})
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Amount</FormLabel>
                  <NumberInput min={0}>
                    <NumberInputField
                      {...depositForm.register('amount', { valueAsNumber: true })}
                      placeholder="0.00"
                    />
                  </NumberInput>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Payment Method</FormLabel>
                  <Select {...depositForm.register('payment_method')} placeholder="Select method">
                    <option value="card">Card Payment</option>
                    <option value="bank_transfer">Bank Transfer</option>
                    <option value="ussd">USSD</option>
                  </Select>
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onDepositClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={depositing} size={{ base: "sm", md: "md" }}>
                Continue
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Withdraw Modal */}
      <Modal isOpen={isWithdrawOpen} onClose={onWithdrawClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={withdrawForm.handleSubmit(handleWithdraw)}>
            <ModalHeader>Withdraw to Bank</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>From Wallet</FormLabel>
                  <Select {...withdrawForm.register('wallet_id')} placeholder="Select wallet">
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Bank</FormLabel>
                  <Select {...withdrawForm.register('bank_code')} placeholder="Select bank">
                    {banks.map((bank: any) => (
                      <option key={bank.code} value={bank.code}>
                        {bank.name}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Account Number</FormLabel>
                  <HStack>
                    <Input {...withdrawForm.register('account_number')} placeholder="0000000000" />
                    <Button type="button" onClick={handleVerifyAccount} isLoading={verifying} size={{ base: "sm", md: "md" }}>
                      Verify
                    </Button>
                  </HStack>
                </FormControl>

                {verifiedAccount && (
                  <FormControl>
                    <FormLabel>Account Name</FormLabel>
                    <Input value={verifiedAccount.account_name} isReadOnly bg="gray.50" />
                  </FormControl>
                )}

                <FormControl isRequired>
                  <FormLabel>Amount</FormLabel>
                  <NumberInput min={0}>
                    <NumberInputField
                      {...withdrawForm.register('amount', { valueAsNumber: true })}
                      placeholder="0.00"
                    />
                  </NumberInput>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Wallet PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...withdrawForm.register('pin')}
                    placeholder="Enter your PIN"
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onWithdrawClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={withdrawing} size={{ base: "sm", md: "md" }}>
                Withdraw
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Dispute Modal */}
      <Modal isOpen={isDisputeOpen} onClose={onDisputeClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={disputeForm.handleSubmit(handleDispute)}>
            <ModalHeader>Create Dispute</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Dispute Type</FormLabel>
                  <Select {...disputeForm.register('dispute_type')} placeholder="Select dispute type">
                    <option value="unauthorized">Unauthorized Transaction</option>
                    <option value="duplicate">Duplicate Charge</option>
                    <option value="not_received">Services/Goods Not Received</option>
                    <option value="defective">Defective Product/Service</option>
                    <option value="refund_not_processed">Refund Not Processed</option>
                    <option value="other">Other</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Reason</FormLabel>
                  <Textarea
                    {...disputeForm.register('reason')}
                    placeholder="Provide detailed explanation about the issue (minimum 10 characters)..."
                    rows={5}
                    minLength={10}
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onDisputeClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button colorScheme="red" type="submit" isLoading={disputing} size={{ base: "sm", md: "md" }}>
                Submit Dispute
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Transaction Details Modal */}
      <Modal isOpen={isDetailsOpen} onClose={onDetailsClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Transaction Details</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedTransaction && (
              <VStack spacing={4} align="stretch">
                {selectedTransaction.reference && (
                  <HStack justify="space-between">
                    <Text color="gray.600">Reference</Text>
                    <Text fontFamily="mono" fontSize="sm">
                      {selectedTransaction.reference || 'N/A'}
                    </Text>
                  </HStack>
                )}
                <HStack justify="space-between">
                  <Text color="gray.600">Type</Text>
                  <Badge>{selectedTransaction.transaction_type || 'N/A'}</Badge>
                </HStack>
                <HStack justify="space-between">
                  <Text color="gray.600">Amount</Text>
                  <Text fontWeight="bold" fontSize="lg">
                    {formatCurrency(selectedTransaction.amount || 0, selectedTransaction.currency || 'NGN')}
                  </Text>
                </HStack>
                <HStack justify="space-between">
                  <Text color="gray.600">Status</Text>
                  <Badge colorScheme={getStatusColor(selectedTransaction.status || 'pending')}>
                    {selectedTransaction.status || 'N/A'}
                  </Badge>
                </HStack>
                {(selectedTransaction.completed_at || selectedTransaction.initiated_at) && (
                  <HStack justify="space-between">
                    <Text color="gray.600">Date</Text>
                    <Text fontSize="sm">
                      {formatDateTime(selectedTransaction.completed_at || selectedTransaction.initiated_at)}
                    </Text>
                  </HStack>
                )}
                {selectedTransaction.description && (
                  <Box>
                    <Text color="gray.600" mb={1}>
                      Description
                    </Text>
                    <Text>{selectedTransaction.description}</Text>
                  </Box>
                )}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onDetailsClose} size={{ base: "sm", md: "md" }}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Container>
  );
};
