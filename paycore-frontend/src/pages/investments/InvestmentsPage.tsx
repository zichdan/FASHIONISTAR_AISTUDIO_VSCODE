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
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
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
  Progress,
  AlertDialog,
  AlertDialogOverlay,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogBody,
  AlertDialogFooter,
} from '@chakra-ui/react';
import {
  FiTrendingUp,
  FiPieChart,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
} from 'react-icons/fi';
import { useState, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import {
  useListInvestmentProductsQuery,
  useLazyCalculateReturnsQuery,
  useCreateInvestmentMutation,
  useListInvestmentsQuery,
  useLiquidateInvestmentMutation,
  useGetPortfolioQuery,
} from '@/features/investments/services/investmentsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import { formatCurrency, formatDate, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError } from '@/utils/errorHandlers';
import { ErrorAlert } from '@/components/common/ErrorAlert';

const COLORS = ['#6366F1', '#22C55E', '#F59E0B', '#EF4444', '#8B5CF6'];
const RISK_COLORS = { low: 'green', medium: 'yellow', high: 'red' };

interface InvestmentForm {
  product_id: string;
  amount: number;
  wallet_id: string;
  pin: string;
}

export const InvestmentsPage = () => {
  const toast = useToast();
  const cancelRef = useRef<HTMLButtonElement>(null);

  const [selectedProduct, setSelectedProduct] = useState<any>(null);
  const [selectedInvestment, setSelectedInvestment] = useState<any>(null);
  const [investAmount, setInvestAmount] = useState(10000);
  const [calculatedReturns, setCalculatedReturns] = useState<any>(null);
  const [liquidateId, setLiquidateId] = useState<string | null>(null);

  const { isOpen: isInvestOpen, onOpen: onInvestOpen, onClose: onInvestClose } = useDisclosure();
  const { isOpen: isCalculatorOpen, onOpen: onCalculatorOpen, onClose: onCalculatorClose } = useDisclosure();
  const { isOpen: isLiquidateOpen, onOpen: onLiquidateOpen, onClose: onLiquidateClose } = useDisclosure();

  const investForm = useForm<InvestmentForm>();

  const { data: productsData, isLoading: loadingProducts, error: productsError } = useListInvestmentProductsQuery({});
  const { data: investmentsData, isLoading: loadingInvestments, error: investmentsError } = useListInvestmentsQuery();
  const { data: portfolioData } = useGetPortfolioQuery();
  const { data: walletsData } = useListWalletsQuery();
  const [calculateReturns, { isLoading: calculating }] = useLazyCalculateReturnsQuery();
  const [createInvestment, { isLoading: investing }] = useCreateInvestmentMutation();
  const [liquidateInvestment, { isLoading: liquidating }] = useLiquidateInvestmentMutation();

  const products = productsData?.data || [];
  const investments = investmentsData?.data?.data || [];
  const portfolio = portfolioData?.data;
  const allWallets = walletsData?.data || [];
  const wallets = allWallets.filter((wallet: any) => wallet.currency?.code === 'NGN');

  const handleCalculate = async () => {
    if (!selectedProduct) return;
    try {
      const result = await calculateReturns({
        product_id: selectedProduct.product_id,
        amount: investAmount,
        duration_days: selectedProduct.min_duration_days || 30,
      }).unwrap();
      setCalculatedReturns(result.data);
    } catch (error: any) {
      toast({ title: 'Calculation failed', description: error.data?.message, status: 'error' });
    }
  };

  const handleInvest = async (data: InvestmentForm) => {
    try {
      await createInvestment({
        ...data,
        amount: Number(data.amount),
        duration_days: selectedProduct?.min_duration_days || 30
      }).unwrap();
      toast({ title: 'Investment created successfully', status: 'success' });
      onInvestClose();
      investForm.reset();
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
        title: 'Investment failed',
        description: errorMessage,
        status: 'error',
        duration: 5000
      });
    }
  };

  const handleLiquidate = async () => {
    if (!liquidateId) return;
    try {
      await liquidateInvestment({
        investment_id: liquidateId,
        accept_penalty: true,
        reason: 'Early liquidation requested by user'
      }).unwrap();
      toast({ title: 'Investment liquidated successfully', status: 'success' });
      onLiquidateClose();
      setLiquidateId(null);
    } catch (error: any) {
      toast({ title: 'Liquidation failed', description: error.data?.message, status: 'error' });
    }
  };

  const portfolioDistribution = investments.map((inv: any) => ({
    name: inv.product_name,
    value: Number(inv.principal_amount),
  }));

  const error = productsError || investmentsError;

  if (error) {
    if (isKYCRequiredError(error)) {
      return (
        <KYCRequired
          title="KYC Verification Required"
          description="To manage your investments, you need to complete your KYC verification first."
        />
      );
    }

    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load investments. Please try again." />
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }}>
      <VStack spacing={{ base: 4, md: 8 }} align="stretch">
        <Stack direction={{ base: 'column', md: 'row' }} justify="space-between" spacing={{ base: 3, md: 0 }}>
          <Box>
            <Heading size={{ base: 'md', md: 'lg' }} mb={2}>Investments</Heading>
            <Text fontSize={{ base: 'sm', md: 'md' }} color="gray.600">Grow your wealth with our investment products</Text>
          </Box>
        </Stack>

        {portfolio && (
          <SimpleGrid columns={{ base: 1, sm: 2, md: 4 }} spacing={{ base: 4, md: 6 }}>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Total Invested</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }}>{formatCurrency(portfolio.total_invested, 'NGN')}</StatNumber>
                  <StatHelpText fontSize={{ base: 'xs', md: 'sm' }}>{portfolio.total_investments} investments</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Expected Returns</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }} color="green.600">{formatCurrency(portfolio.total_returns, 'NGN')}</StatNumber>
                  <StatHelpText fontSize={{ base: 'xs', md: 'sm' }}>{portfolio.average_return_rate}% avg rate</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Active Investments</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }}>{portfolio.active_investments}</StatNumber>
                  <StatHelpText fontSize={{ base: 'xs', md: 'sm' }}>Currently running</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel fontSize={{ base: 'xs', md: 'sm' }}>Matured</StatLabel>
                  <StatNumber fontSize={{ base: 'lg', md: 'xl' }}>{portfolio.matured_investments}</StatNumber>
                  <StatHelpText fontSize={{ base: 'xs', md: 'sm' }}>Completed</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        <Tabs>
          <TabList>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Investment Products</Tab>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>My Investments</Tab>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Portfolio</Tab>
          </TabList>

          <TabPanels>
            <TabPanel px={0}>
              {loadingProducts ? (
                <SimpleGrid columns={{ base: 1, sm: 2, md: 3 }} spacing={{ base: 4, md: 6 }}>
                  {[1, 2, 3].map((i) => <Skeleton key={i} height="250px" />)}
                </SimpleGrid>
              ) : (
                <SimpleGrid columns={{ base: 1, sm: 2, md: 3 }} spacing={{ base: 4, md: 6 }}>
                  {products.map((product: any) => (
                    <Card key={product.product_id} _hover={{ shadow: 'lg' }}>
                      <CardBody>
                        <VStack align="stretch" spacing={{ base: 3, md: 4 }}>
                          <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" align={{ base: 'start', sm: 'center' }} spacing={{ base: 2, sm: 0 }}>
                            <Heading size={{ base: 'sm', md: 'md' }}>{product.name}</Heading>
                            <Badge colorScheme={RISK_COLORS[product.risk_level as keyof typeof RISK_COLORS]} fontSize={{ base: 'xs', md: 'sm' }}>
                              {product.risk_level} risk
                            </Badge>
                          </Stack>
                          <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600" noOfLines={2}>{product.description}</Text>
                          <VStack align="stretch" spacing={2}>
                            <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                              <Text color="gray.600">Minimum Amount</Text>
                              <Text fontWeight="600">{formatCurrency(product.min_amount, 'NGN')}</Text>
                            </HStack>
                            <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                              <Text color="gray.600">Return Rate</Text>
                              <Text fontWeight="600" color="green.600">{product.return_rate}% p.a.</Text>
                            </HStack>
                            <HStack justify="space-between" fontSize={{ base: 'xs', md: 'sm' }}>
                              <Text color="gray.600">Duration</Text>
                              <Text fontWeight="600">{product.duration_months} months</Text>
                            </HStack>
                          </VStack>
                          <Stack direction={{ base: 'column', sm: 'row' }} spacing={2}>
                            <Button size={{ base: 'xs', md: 'sm' }} variant="outline" flex={1} onClick={() => {
                              setSelectedProduct(product);
                              setInvestAmount(product.min_amount);
                              onCalculatorOpen();
                            }}>Calculate</Button>
                            <Button size={{ base: 'xs', md: 'sm' }} colorScheme="brand" flex={1} onClick={() => {
                              setSelectedProduct(product);
                              investForm.setValue('product_id', product.product_id);
                              onInvestOpen();
                            }}>Invest Now</Button>
                          </Stack>
                        </VStack>
                      </CardBody>
                    </Card>
                  ))}
                </SimpleGrid>
              )}
            </TabPanel>

            <TabPanel px={0}>
              {loadingInvestments ? (
                <LoadingSpinner />
              ) : investments.length > 0 ? (
                <VStack spacing={{ base: 3, md: 4 }} align="stretch">
                  {investments.map((inv: any) => (
                    <Card key={inv.investment_id}>
                      <CardBody>
                        <VStack align="stretch" spacing={{ base: 3, md: 4 }}>
                          <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" align={{ base: 'start', sm: 'center' }} spacing={{ base: 2, sm: 0 }}>
                            <VStack align="start" spacing={1}>
                              <Heading size={{ base: 'xs', md: 'sm' }}>{inv.product_name}</Heading>
                              <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600">
                                {inv.product_type} • {inv.days_to_maturity} days to maturity
                              </Text>
                            </VStack>
                            <Badge colorScheme={getStatusColor(inv.status)} fontSize={{ base: 'xs', md: 'sm' }} px={3} py={1}>
                              {inv.status}
                            </Badge>
                          </Stack>
                          <SimpleGrid columns={{ base: 2, sm: 2, md: 4 }} spacing={{ base: 3, md: 4 }}>
                            <Box>
                              <Text fontSize="xs" color="gray.600" mb={1}>Principal</Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>
                                {formatCurrency(Number(inv.principal_amount), inv.currency?.code || 'NGN')}
                              </Text>
                            </Box>
                            <Box>
                              <Text fontSize="xs" color="gray.600" mb={1}>Expected Returns</Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }} color="green.600">
                                {formatCurrency(Number(inv.expected_returns), inv.currency?.code || 'NGN')}
                              </Text>
                            </Box>
                            <Box>
                              <Text fontSize="xs" color="gray.600" mb={1}>Maturity Date</Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>{formatDate(inv.maturity_date)}</Text>
                            </Box>
                            <Box>
                              <Text fontSize="xs" color="gray.600" mb={1}>Days to Maturity</Text>
                              <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>{inv.days_to_maturity} days</Text>
                            </Box>
                          </SimpleGrid>
                          {inv.status === 'active' && (
                            <Button size={{ base: 'xs', md: 'sm' }} colorScheme="red" variant="outline" onClick={() => {
                              setLiquidateId(inv.investment_id);
                              onLiquidateOpen();
                            }}>
                              Liquidate Early
                            </Button>
                          )}
                        </VStack>
                      </CardBody>
                    </Card>
                  ))}
                </VStack>
              ) : (
                <EmptyState icon={FiPieChart} title="No investments yet" description="Start investing to build your portfolio" />
              )}
            </TabPanel>

            <TabPanel px={0}>
              <SimpleGrid columns={{ base: 1, sm: 1, lg: 2 }} spacing={{ base: 4, md: 6 }}>
                <Card>
                  <CardBody>
                    <Heading size={{ base: 'xs', md: 'sm' }} mb={4}>Portfolio Distribution</Heading>
                    {portfolioDistribution.length > 0 ? (
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie data={portfolioDistribution} cx="50%" cy="50%" labelLine={false}
                            label={(entry) => entry.name} outerRadius={80} fill="#8884d8" dataKey="value">
                            {portfolioDistribution.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip formatter={(value: number) => formatCurrency(value, 'NGN')} />
                        </PieChart>
                      </ResponsiveContainer>
                    ) : (
                      <EmptyState icon={FiPieChart} title="No data" description="Start investing to see your portfolio distribution" />
                    )}
                  </CardBody>
                </Card>
                <Card>
                  <CardBody>
                    <Heading size={{ base: 'xs', md: 'sm' }} mb={4}>Investment Performance</Heading>
                    {investments.length > 0 ? (
                      <VStack align="stretch" spacing={3}>
                        {investments.slice(0, 5).map((inv: any) => {
                          const returnRate = inv.principal_amount > 0
                            ? ((Number(inv.expected_returns) / Number(inv.principal_amount)) * 100).toFixed(2)
                            : '0';
                          return (
                            <Box key={inv.investment_id}>
                              <HStack justify="space-between" mb={1}>
                                <Text fontSize={{ base: 'xs', md: 'sm' }}>{inv.product_name}</Text>
                                <Text fontSize={{ base: 'xs', md: 'sm' }} fontWeight="600">{returnRate}%</Text>
                              </HStack>
                              <Progress value={Number(returnRate)} max={100} colorScheme="green" size="sm" borderRadius="full" />
                            </Box>
                          );
                        })}
                      </VStack>
                    ) : (
                      <EmptyState icon={FiTrendingUp} title="No data" />
                    )}
                  </CardBody>
                </Card>
              </SimpleGrid>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>

      {/* Calculator Modal */}
      <Modal isOpen={isCalculatorOpen} onClose={onCalculatorClose} size={{ base: 'full', md: 'lg' }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Returns Calculator</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={{ base: 4, md: 6 }} align="stretch">
              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Investment Amount: {formatCurrency(investAmount, 'NGN')}</FormLabel>
                <Slider value={investAmount} onChange={setInvestAmount}
                  min={Number(selectedProduct?.min_amount) || 1000} max={Number(selectedProduct?.max_amount) || 1000000} step={1000}>
                  <SliderTrack><SliderFilledTrack bg="brand.500" /></SliderTrack>
                  <SliderThumb boxSize={{ base: 5, md: 6 }} />
                </Slider>
              </FormControl>
              <Button onClick={handleCalculate} isLoading={calculating} colorScheme="brand" size={{ base: 'sm', md: 'md' }}>Calculate Returns</Button>
              {calculatedReturns && (
                <Card bg="brand.50">
                  <CardBody>
                    <VStack align="stretch" spacing={3}>
                      <Heading size={{ base: 'xs', md: 'sm' }}>Projected Returns</Heading>
                      <HStack justify="space-between">
                        <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>Principal</Text>
                        <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>{formatCurrency(Number(calculatedReturns.amount), 'NGN')}</Text>
                      </HStack>
                      <HStack justify="space-between">
                        <Text color="gray.600" fontSize={{ base: 'sm', md: 'md' }}>Returns ({calculatedReturns.interest_rate}%)</Text>
                        <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }} color="green.600">
                          {formatCurrency(Number(calculatedReturns.expected_returns), 'NGN')}
                        </Text>
                      </HStack>
                      <Divider />
                      <HStack justify="space-between">
                        <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>Total at Maturity</Text>
                        <Text fontWeight="bold" fontSize={{ base: 'md', md: 'lg' }} color="brand.600">
                          {formatCurrency(Number(calculatedReturns.total_maturity_value), 'NGN')}
                        </Text>
                      </HStack>
                    </VStack>
                  </CardBody>
                </Card>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onCalculatorClose} size={{ base: 'sm', md: 'md' }}>Close</Button>
            <Button colorScheme="brand" onClick={() => {
              onCalculatorClose();
              setSelectedProduct(selectedProduct);
              investForm.setValue('product_id', selectedProduct.product_id);
              onInvestOpen();
            }} size={{ base: 'sm', md: 'md' }}>Invest Now</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Investment Modal */}
      <Modal isOpen={isInvestOpen} onClose={onInvestClose} size={{ base: 'full', md: 'md' }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={investForm.handleSubmit(handleInvest)}>
            <ModalHeader fontSize={{ base: 'md', md: 'lg' }}>Make Investment</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={{ base: 3, md: 4 }}>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Amount</FormLabel>
                  <NumberInput min={Number(selectedProduct?.min_amount)} max={Number(selectedProduct?.max_amount)} size={{ base: 'sm', md: 'md' }}>
                    <NumberInputField {...investForm.register('amount', { valueAsNumber: true })} placeholder="0.00" />
                  </NumberInput>
                </FormControl>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Source Wallet</FormLabel>
                  <Select {...investForm.register('wallet_id')} placeholder="Select wallet" size={{ base: 'sm', md: 'md' }}>
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Wallet PIN</FormLabel>
                  <Input type="password" maxLength={4} {...investForm.register('pin')} placeholder="Enter PIN" size={{ base: 'sm', md: 'md' }} />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onInvestClose} size={{ base: 'sm', md: 'md' }}>Cancel</Button>
              <Button colorScheme="brand" type="submit" isLoading={investing} size={{ base: 'sm', md: 'md' }}>Invest Now</Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Liquidate Confirmation */}
      <AlertDialog isOpen={isLiquidateOpen} leastDestructiveRef={cancelRef} onClose={onLiquidateClose}>
        <AlertDialogOverlay>
          <AlertDialogContent mx={{ base: 4, md: 0 }}>
            <AlertDialogHeader fontSize={{ base: 'md', md: 'lg' }}>Liquidate Investment</AlertDialogHeader>
            <AlertDialogBody fontSize={{ base: 'sm', md: 'md' }}>
              Early liquidation may result in penalties. Are you sure you want to proceed?
            </AlertDialogBody>
            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onLiquidateClose} size={{ base: 'sm', md: 'md' }}>Cancel</Button>
              <Button colorScheme="red" onClick={handleLiquidate} ml={3} isLoading={liquidating} size={{ base: 'sm', md: 'md' }}>
                Liquidate
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>
    </Container>
  );
};
