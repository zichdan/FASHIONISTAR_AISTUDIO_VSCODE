import {
  Box,
  Container,
  Grid,
  GridItem,
  Heading,
  Text,
  VStack,
  HStack,
  Card,
  CardBody,
  Button,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  StatArrow,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Icon,
  SimpleGrid,
  useDisclosure,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Skeleton,
  SkeletonText,
} from '@chakra-ui/react';
import { FiTrendingUp, FiSend, FiDownload, FiFileText, FiCreditCard, FiPieChart, FiArrowUpRight, FiArrowDownRight } from 'react-icons/fi';
import { MdAccountBalanceWallet } from 'react-icons/md';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useGetWalletSummaryQuery } from '@/features/wallets/services/walletsApi';
import { useListTransactionsQuery, useGetTransactionStatisticsQuery } from '@/features/transactions/services/transactionsApi';
import { useGetLoanSummaryQuery } from '@/features/loans/services/loansApi';
import { useGetPortfolioQuery } from '@/features/investments/services/investmentsApi';
import { useGetCurrentKYCLevelQuery } from '@/features/compliance/services/complianceApi';
import { formatCurrency, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { useNavigate } from 'react-router-dom';
import { isKYCRequiredError } from '@/utils/errorHandlers';

const COLORS = ['#6366F1', '#22C55E', '#F59E0B', '#EF4444'];

export const DashboardPage = () => {
  const navigate = useNavigate();

  // Fetch data
  const { data: walletSummary, isLoading: loadingWallets, error: walletError } = useGetWalletSummaryQuery();
  const { data: transactionsData, isLoading: loadingTransactions, error: transactionsError } = useListTransactionsQuery({ limit: 5 });
  const { data: statisticsData, isLoading: loadingStats, error: statsError } = useGetTransactionStatisticsQuery();
  const { data: loanSummary, isLoading: loadingLoans, error: loansError } = useGetLoanSummaryQuery();
  const { data: portfolio, isLoading: loadingInvestments, error: portfolioError } = useGetPortfolioQuery();
  const { data: kycLevel } = useGetCurrentKYCLevelQuery();

  const walletData = walletSummary?.data;
  // Backend returns transactions directly in data.transactions, not data.data.transactions
  const transactions = (transactionsData?.data as any)?.transactions || [];
  const statistics = statisticsData?.data;
  const loans = loanSummary?.data;
  const investments = portfolio?.data;
  const kyc = kycLevel?.data;

  // Extract NGN balance data from the summary (backend returns total_balances object keyed by currency)
  const ngnBalance = walletData?.total_balances?.['NGN'] || {
    total_balance: 0,
    total_available: 0,
    total_pending: 0,
    symbol: '₦',
    wallet_count: 0
  };

  // Calculate total holds (balance - available)
  const totalHolds = (ngnBalance.total_balance || 0) - (ngnBalance.total_available || 0);

  // Prepare chart data
  // Backend doesn't provide daily_statistics, so we'll use transaction data to create a simple trend
  const transactionTrend = transactions.slice(0, 5).reverse().map((transaction: any, index: number) => ({
    date: new Date(transaction.initiated_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    amount: parseFloat(transaction.amount),
    count: index + 1,
  }));

  // Portfolio Distribution - use actual field names from backend
  const walletDistribution = [
    { name: 'Main Wallet', value: parseFloat(ngnBalance.total_balance?.toString() || '0') },
    { name: 'Loans', value: parseFloat(loans?.total_borrowed || '0') },
    { name: 'Investments', value: parseFloat(investments?.total_invested || '0') },
  ].filter(item => item.value > 0); // Only show non-zero values

  const quickActions = [
    {
      icon: FiSend,
      label: 'Send Money',
      description: 'Transfer to wallets or banks',
      color: 'brand',
      onClick: () => navigate('/transactions'),
    },
    {
      icon: FiDownload,
      label: 'Add Money',
      description: 'Fund your wallet',
      color: 'green',
      onClick: () => navigate('/transactions'),
    },
    {
      icon: FiFileText,
      label: 'Pay Bills',
      description: 'Airtime, data, utilities',
      color: 'purple',
      onClick: () => navigate('/bills'),
    },
    {
      icon: FiPieChart,
      label: 'Invest',
      description: 'Grow your wealth',
      color: 'orange',
      onClick: () => navigate('/investments'),
    },
  ];

  if (loadingWallets) {
    return (
      <Container maxW="container.xl" py={8}>
        <VStack spacing={8} align="stretch">
          <Skeleton height="200px" borderRadius="xl" />
          <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6}>
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} height="120px" borderRadius="lg" />
            ))}
          </SimpleGrid>
          <Skeleton height="400px" borderRadius="xl" />
        </VStack>
      </Container>
    );
  }

  if (walletError) {
    if (isKYCRequiredError(walletError)) {
      return (
        <KYCRequired
          title="KYC Verification Required"
          description="To access your wallet and start using PayCore, you need to complete your KYC verification first."
        />
      );
    }

    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load dashboard data. Please try again." />
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Box>
          <Heading size={{ base: "md", md: "lg" }} mb={2}>
            Dashboard
          </Heading>
          <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Welcome back! Here's your financial overview.</Text>
        </Box>

        {/* KYC Alert */}
        {kyc && kyc.current_level !== 'TIER_3' && (
          <Alert status="warning" borderRadius="lg">
            <AlertIcon />
            <Box flex="1">
              <AlertTitle>Complete Your Verification</AlertTitle>
              <AlertDescription>
                You're currently at {kyc.current_level}. Upgrade to unlock higher limits and more features.
              </AlertDescription>
            </Box>
            <Button
              colorScheme="orange"
              size="sm"
              onClick={() => navigate('/profile')}
            >
              Verify Now
            </Button>
          </Alert>
        )}

        {/* Wallet Summary */}
        <Card bgGradient="linear(to-br, brand.500, brand.700)" color="white" shadow="xl">
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <HStack justify="space-between" align="start">
                <VStack align="start" spacing={1} flex="1" minW={0}>
                  <Text fontSize={{ base: "xs", md: "sm" }} opacity={0.9}>
                    Total Balance
                  </Text>
                  <Heading
                    size={{ base: "lg", md: "2xl" }}
                    wordBreak="break-word"
                    overflowWrap="break-word"
                    lineHeight="shorter"
                  >
                    {formatCurrency(ngnBalance.total_balance, 'NGN')}
                  </Heading>
                  <Text fontSize={{ base: "xs", md: "sm" }} opacity={0.8}>
                    Across {walletData?.wallet_count || 0} wallet{walletData?.wallet_count !== 1 ? 's' : ''}
                  </Text>
                </VStack>
                <Icon
                  as={MdAccountBalanceWallet}
                  boxSize={{ base: 10, md: 16 }}
                  opacity={0.2}
                  flexShrink={0}
                />
              </HStack>

              <SimpleGrid columns={{ base: 2, md: 3 }} spacing={4} pt={4} borderTop="1px" borderColor="whiteAlpha.300">
                <Box minW={0}>
                  <Text fontSize="xs" opacity={0.8} mb={1}>
                    Available
                  </Text>
                  <Text
                    fontSize={{ base: "sm", md: "lg" }}
                    fontWeight="bold"
                    wordBreak="break-word"
                    overflowWrap="break-word"
                  >
                    {formatCurrency(ngnBalance.total_available, 'NGN')}
                  </Text>
                </Box>
                <Box minW={0}>
                  <Text fontSize="xs" opacity={0.8} mb={1}>
                    On Hold
                  </Text>
                  <Text
                    fontSize={{ base: "sm", md: "lg" }}
                    fontWeight="bold"
                    wordBreak="break-word"
                    overflowWrap="break-word"
                  >
                    {formatCurrency(totalHolds, 'NGN')}
                  </Text>
                </Box>
                <Box minW={0}>
                  <Text fontSize="xs" opacity={0.8} mb={1}>
                    Active Wallets
                  </Text>
                  <Text fontSize={{ base: "sm", md: "lg" }} fontWeight="bold">
                    {ngnBalance.wallet_count}
                  </Text>
                </Box>
              </SimpleGrid>
            </VStack>
          </CardBody>
        </Card>

        {/* Quick Actions */}
        <Box>
          <Heading size={{ base: "sm", md: "md" }} mb={4}>
            Quick Actions
          </Heading>
          <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
            {quickActions.map((action) => (
              <Card
                key={action.label}
                cursor="pointer"
                transition="all 0.2s"
                _hover={{ transform: 'translateY(-4px)', shadow: 'lg' }}
                onClick={action.onClick}
              >
                <CardBody py={{ base: 4, md: 6 }}>
                  <VStack spacing={{ base: 2, md: 3 }}>
                    <Icon
                      as={action.icon}
                      boxSize={{ base: 6, md: 8 }}
                      color={`${action.color}.500`}
                    />
                    <VStack spacing={1}>
                      <Text fontWeight="600" fontSize={{ base: "xs", md: "sm" }}>
                        {action.label}
                      </Text>
                      <Text fontSize={{ base: "2xs", md: "xs" }} color="gray.500" textAlign="center">
                        {action.description}
                      </Text>
                    </VStack>
                  </VStack>
                </CardBody>
              </Card>
            ))}
          </SimpleGrid>
        </Box>

        {/* Stats Grid */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6}>
          <Card>
            <CardBody>
              <Stat>
                <StatLabel>Total Transactions</StatLabel>
                <StatNumber>{statistics?.total_transactions || 0}</StatNumber>
                <StatHelpText>
                  <StatArrow type="increase" />
                  {statistics?.growth_percentage || 0}% this month
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>Active Loans</StatLabel>
                <StatNumber>{loans?.active_loans || 0}</StatNumber>
                <StatHelpText>
                  {formatCurrency(loans?.total_outstanding || 0, 'NGN')} outstanding
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>Investments</StatLabel>
                <StatNumber>{investments?.total_investments || 0}</StatNumber>
                <StatHelpText>
                  {formatCurrency(investments?.total_invested || 0, 'NGN')} invested
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>Expected Returns</StatLabel>
                <StatNumber fontSize="xl">
                  {formatCurrency(investments?.total_returns || 0, 'NGN')}
                </StatNumber>
                <StatHelpText>
                  <StatArrow type="increase" />
                  {investments?.average_return_rate || 0}% avg rate
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Charts */}
        <Grid templateColumns={{ base: '1fr', lg: '2fr 1fr' }} gap={6}>
          <GridItem>
            <Card>
              <CardBody>
                <Heading size="sm" mb={4}>
                  Transaction Trend
                </Heading>
                {loadingStats ? (
                  <Skeleton height="300px" />
                ) : transactionTrend.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={transactionTrend}>
                      <defs>
                        <linearGradient id="colorAmount" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366F1" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#6366F1" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" />
                      <YAxis />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="amount"
                        stroke="#6366F1"
                        fillOpacity={1}
                        fill="url(#colorAmount)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <EmptyState
                    icon={FiTrendingUp}
                    title="No transaction data yet"
                    description="Start making transactions to see your trends"
                  />
                )}
              </CardBody>
            </Card>
          </GridItem>

          <GridItem>
            <Card>
              <CardBody>
                <Heading size="sm" mb={4}>
                  Portfolio Distribution
                </Heading>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={walletDistribution}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={(entry) => entry.name}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {walletDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value: number) => formatCurrency(value, 'NGN')} />
                  </PieChart>
                </ResponsiveContainer>
              </CardBody>
            </Card>
          </GridItem>
        </Grid>

        {/* Recent Transactions */}
        <Card>
          <CardBody>
            <HStack justify="space-between" mb={4}>
              <Heading size={{ base: "xs", md: "sm" }}>Recent Transactions</Heading>
              <Button
                size={{ base: "xs", md: "sm" }}
                variant="ghost"
                rightIcon={<Icon as={FiArrowUpRight} />}
                onClick={() => navigate('/transactions')}
              >
                View All
              </Button>
            </HStack>

            {loadingTransactions ? (
              <VStack spacing={3}>
                {[1, 2, 3, 4, 5].map((i) => (
                  <SkeletonText key={i} noOfLines={2} spacing={2} width="100%" />
                ))}
              </VStack>
            ) : transactions.length > 0 ? (
              <Box overflowX="auto">
                <Table variant="simple" size={{ base: "sm", md: "md" }}>
                  <Thead>
                    <Tr>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Type</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Reference</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Amount</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }}>Status</Th>
                      <Th fontSize={{ base: "xs", md: "sm" }} display={{ base: "none", md: "table-cell" }}>Date</Th>
                    </Tr>
                  </Thead>
                <Tbody>
                  {transactions.map((transaction: any) => {
                    // Determine if transaction is credit (incoming) or debit (outgoing)
                    // Credit: loan_disbursement, investment_payout, transfer (when to_user exists)
                    // Debit: investment, bill_payment, transfer (when from_user exists)
                    const isCredit = transaction.to_user_name && !transaction.from_user_name;

                    return (
                      <Tr key={transaction.transaction_id}>
                        <Td fontSize={{ base: "xs", md: "sm" }}>
                          <HStack spacing={{ base: 1, md: 2 }}>
                            <Icon
                              as={isCredit ? FiArrowDownRight : FiArrowUpRight}
                              color={isCredit ? 'green.500' : 'red.500'}
                              boxSize={{ base: 3, md: 4 }}
                            />
                            <Text textTransform="capitalize" isTruncated maxW={{ base: "80px", md: "none" }}>{transaction.transaction_type?.replace(/_/g, ' ')}</Text>
                          </HStack>
                        </Td>
                        <Td fontFamily="mono" fontSize={{ base: "xs", md: "sm" }} isTruncated maxW={{ base: "100px", md: "none" }}>
                          {transaction.reference || '-'}
                        </Td>
                        <Td fontWeight="600" fontSize={{ base: "xs", md: "sm" }}>
                          <Text color={isCredit ? 'green.600' : 'red.600'}>
                            {isCredit ? '+' : '-'}
                            {formatCurrency(transaction.amount, transaction.currency_code || 'NGN')}
                          </Text>
                        </Td>
                        <Td>
                          <Badge colorScheme={getStatusColor(transaction.status)} fontSize={{ base: "2xs", md: "xs" }}>
                            {transaction.status}
                          </Badge>
                        </Td>
                        <Td fontSize={{ base: "xs", md: "sm" }} color="gray.600" display={{ base: "none", md: "table-cell" }}>
                          {formatRelativeTime(transaction.initiated_at)}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
              </Box>
            ) : (
              <EmptyState
                icon={FiFileText}
                title="No transactions yet"
                description="Your recent transactions will appear here"
              />
            )}
          </CardBody>
        </Card>
      </VStack>
    </Container>
  );
};
