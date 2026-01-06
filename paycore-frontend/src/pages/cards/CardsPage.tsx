import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  HStack,
  Stack,
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
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Switch,
  AlertDialog,
  AlertDialogOverlay,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogBody,
  AlertDialogFooter,
  Skeleton,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  IconButton,
  Divider,
  Image,
} from '@chakra-ui/react';
import {
  FiCreditCard,
  FiPlus,
  FiMoreVertical,
  FiLock,
  FiUnlock,
  FiShield,
  FiDollarSign,
  FiGlobe,
  FiShoppingCart,
  FiEye,
  FiEyeOff,
  FiTrash2,
} from 'react-icons/fi';
import { useState, useRef } from 'react';
import { useForm } from 'react-hook-form';
import {
  useListCardsQuery,
  useCreateCardMutation,
  useDeleteCardMutation,
  useFundCardMutation,
  useFreezeCardMutation,
  useUnfreezeCardMutation,
  useBlockCardMutation,
  useActivateCardMutation,
  useUpdateCardControlsMutation,
  useGetCardTransactionsQuery,
} from '@/features/cards/services/cardsApi';
import { useListWalletsQuery, useListCurrenciesQuery } from '@/features/wallets/services/walletsApi';
import { formatCurrency, formatRelativeTime, getStatusColor, maskCardNumber } from '@/utils/formatters';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { EmptyState } from '@/components/common/EmptyState';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError, getErrorMessage } from '@/utils/errorHandlers';

interface CreateCardForm {
  wallet_id: string;
  card_type: string;
  card_brand: string;
  currency_code: string;
  nickname?: string;
}

interface FundCardForm {
  amount: string;
  pin?: string;
}

export const CardsPage = () => {
  const toast = useToast();
  const cancelRef = useRef<HTMLButtonElement>(null);

  // State
  const [selectedCard, setSelectedCard] = useState<any>(null);
  const [deleteCardId, setDeleteCardId] = useState<string | null>(null);
  const [showCardNumber, setShowCardNumber] = useState<{ [key: string]: boolean }>({});
  const [showCvv, setShowCvv] = useState<{ [key: string]: boolean }>({});

  // Modals
  const { isOpen: isCreateOpen, onOpen: onCreateOpen, onClose: onCreateClose } = useDisclosure();
  const { isOpen: isFundOpen, onOpen: onFundOpen, onClose: onFundClose } = useDisclosure();
  const { isOpen: isControlsOpen, onOpen: onControlsOpen, onClose: onControlsClose } = useDisclosure();
  const { isOpen: isDeleteOpen, onOpen: onDeleteOpen, onClose: onDeleteClose } = useDisclosure();
  const { isOpen: isDetailsOpen, onOpen: onDetailsOpen, onClose: onDetailsClose } = useDisclosure();

  // Forms
  const createForm = useForm<CreateCardForm>();
  const fundForm = useForm<FundCardForm>();

  // API
  const { data: cardsData, isLoading, error } = useListCardsQuery();
  const { data: walletsData } = useListWalletsQuery();
  const { data: currenciesData } = useListCurrenciesQuery();
  const [createCard, { isLoading: creating }] = useCreateCardMutation();
  const [deleteCard, { isLoading: deleting }] = useDeleteCardMutation();
  const [fundCard, { isLoading: funding }] = useFundCardMutation();
  const [freezeCard] = useFreezeCardMutation();
  const [unfreezeCard] = useUnfreezeCardMutation();
  const [blockCard] = useBlockCardMutation();
  const [activateCard] = useActivateCardMutation();
  const [updateCardControls] = useUpdateCardControlsMutation();

  const cards = cardsData?.data || [];
  const wallets = walletsData?.data || [];
  const currencies = currenciesData?.data || [];

  // Handlers
  const handleCreate = async (data: CreateCardForm) => {
    try {
      await createCard(data).unwrap();
      // Success notification will be sent via WebSocket
      onCreateClose();
      createForm.reset();
    } catch (error: any) {
      toast({
        title: 'Failed to create card',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleFund = async (data: FundCardForm) => {
    if (!selectedCard) return;
    try {
      await fundCard({
        cardId: selectedCard.card_id,
        data: {
          amount: Number(data.amount),
          pin: data.pin ? Number(data.pin) : undefined,
        },
      }).unwrap();
      toast({
        title: 'Card funded successfully',
        status: 'success',
        duration: 3000,
      });
      onFundClose();
      fundForm.reset();
      setSelectedCard(null);
    } catch (error: any) {
      toast({
        title: 'Failed to fund card',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleDelete = async () => {
    if (!deleteCardId) return;
    try {
      await deleteCard(deleteCardId).unwrap();
      toast({
        title: 'Card deleted successfully',
        status: 'success',
        duration: 3000,
      });
      onDeleteClose();
      setDeleteCardId(null);
    } catch (error: any) {
      toast({
        title: 'Failed to delete card',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleFreeze = async (cardId: string, freeze: boolean) => {
    try {
      if (freeze) {
        await freezeCard(cardId).unwrap();
      } else {
        await unfreezeCard(cardId).unwrap();
      }
      toast({
        title: `Card ${freeze ? 'frozen' : 'unfrozen'} successfully`,
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: `Failed to ${freeze ? 'freeze' : 'unfreeze'} card`,
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleBlock = async (cardId: string) => {
    // Show confirmation since this is permanent
    const confirmed = window.confirm(
      'Are you sure you want to block this card permanently?\n\n' +
      'This action CANNOT be undone. Blocked cards cannot be unblocked.\n\n' +
      'If you might want to use this card again, consider using "Freeze Card" instead.'
    );

    if (!confirmed) return;

    try {
      await blockCard(cardId).unwrap();
      toast({
        title: 'Card blocked permanently',
        description: 'This action cannot be undone',
        status: 'warning',
        duration: 5000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to block card',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleActivate = async (cardId: string) => {
    try {
      await activateCard(cardId).unwrap();
      toast({
        title: 'Card activated successfully',
        description: 'Your card is now ready to use',
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to activate card',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleControlToggle = async (card: any, control: string, value: boolean) => {
    try {
      // Backend requires all three fields, so we send current values with the updated one
      const data = {
        allow_online_transactions: card.allow_online_transactions,
        allow_atm_withdrawals: card.allow_atm_withdrawals,
        allow_international_transactions: card.allow_international_transactions,
        [control]: value, // Override the specific control being changed
      };

      await updateCardControls({
        cardId: card.card_id,
        data,
      }).unwrap();

      // Update the selected card state to reflect the change immediately
      setSelectedCard({ ...card, [control]: value });

      toast({
        title: 'Card controls updated',
        status: 'success',
        duration: 2000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to update controls',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const openFundModal = (card: any) => {
    setSelectedCard(card);
    fundForm.reset();
    onFundOpen();
  };

  const openControlsModal = (card: any) => {
    setSelectedCard(card);
    onControlsOpen();
  };

  const openDetailsModal = (card: any) => {
    setSelectedCard(card);
    onDetailsOpen();
  };

  const toggleCardNumber = (cardId: string) => {
    setShowCardNumber((prev) => ({ ...prev, [cardId]: !prev[cardId] }));
  };

  const toggleCvv = (cardId: string) => {
    setShowCvv((prev) => ({ ...prev, [cardId]: !prev[cardId] }));
  };

  const getCardBrandColor = (brand: string | undefined) => {
    if (!brand) return '#805AD5'; // purple.600

    const colors: { [key: string]: string } = {
      visa: '#2B6CB0', // blue.600
      mastercard: '#C05621', // orange.600
      verve: '#2F855A', // green.600
    };
    return colors[brand.toLowerCase()] || '#805AD5';
  };

  const getCardBrandColorDark = (brand: string | undefined) => {
    if (!brand) return '#6B46C1'; // purple.800

    const colors: { [key: string]: string } = {
      visa: '#2C5282', // blue.800
      mastercard: '#9C4221', // orange.800
      verve: '#276749', // green.800
    };
    return colors[brand.toLowerCase()] || '#6B46C1';
  };

  if (isLoading) {
    return (
      <Container maxW="container.xl" py={8}>
        <VStack spacing={6} align="stretch">
          <Skeleton height="60px" />
          <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="220px" borderRadius="xl" />
            ))}
          </SimpleGrid>
        </VStack>
      </Container>
    );
  }

  if (error) {
    if (isKYCRequiredError(error)) {
      return (
        <KYCRequired
          title="KYC Verification Required"
          description="To manage your cards, you need to complete your KYC verification first."
        />
      );
    }

    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load cards. Please try again." />
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Stack direction={{ base: "column", md: "row" }} justify="space-between" spacing={{ base: 4, md: 0 }} align={{ base: "stretch", md: "center" }}>
          <Box>
            <Heading size={{ base: "md", md: "lg" }} mb={2}>
              My Cards
            </Heading>
            <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Manage your virtual and physical cards</Text>
          </Box>
          <Button leftIcon={<Icon as={FiPlus} />} colorScheme="brand" onClick={onCreateOpen} size={{ base: "sm", md: "md" }} width={{ base: "full", md: "auto" }}>
            Create Card
          </Button>
        </Stack>

        {/* Cards Grid */}
        {cards.length > 0 ? (
          <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
            {cards.map((card: any) => (
              <Box
                key={card.card_id}
                position="relative"
              >
                <Box
                  sx={{
                    background: `linear-gradient(135deg, ${getCardBrandColor(card.card_brand)} 0%, ${getCardBrandColorDark(card.card_brand)} 100%)`,
                    color: 'white',
                    position: 'relative',
                    overflow: 'hidden',
                    borderRadius: 'lg',
                    boxShadow: 'md',
                    transition: 'all 0.2s',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: '2xl',
                    },
                  }}
                >
                  {/* Card Background Pattern */}
                  <Box
                    position="absolute"
                    top="-50%"
                    right="-20%"
                    width="200px"
                    height="200px"
                    borderRadius="full"
                    bg="whiteAlpha.100"
                    zIndex={0}
                  />
                  <Box
                    position="absolute"
                    bottom="-30%"
                    left="-10%"
                    width="150px"
                    height="150px"
                    borderRadius="full"
                    bg="whiteAlpha.100"
                    zIndex={0}
                  />

                  <Box position="relative" zIndex={1} p={6}>
                  <VStack align="stretch" spacing={4} h="full">
                    {/* Card Type & Brand */}
                    <HStack justify="space-between">
                      <Badge colorScheme="whiteAlpha" variant="solid">
                        {card.card_type}
                      </Badge>
                      <Text fontSize="lg" fontWeight="bold" textTransform="uppercase">
                        {card.card_brand}
                      </Text>
                    </HStack>

                    {/* Card Number */}
                    <Box>
                      <HStack mb={1}>
                        <Text fontSize="xs" opacity={0.8}>
                          Card Number
                        </Text>
                        <IconButton
                          aria-label="Toggle card number"
                          icon={<Icon as={showCardNumber[card.card_id] ? FiEyeOff : FiEye} />}
                          size="xs"
                          variant="ghost"
                          color="white"
                          onClick={() => toggleCardNumber(card.card_id)}
                        />
                      </HStack>
                      <Text fontSize="lg" fontFamily="mono" letterSpacing="wide">
                        {showCardNumber[card.card_id] && card.card_number
                          ? card.card_number.match(/.{1,4}/g)?.join(' ')
                          : card.masked_number || '**** **** **** ****'}
                      </Text>
                    </Box>

                    {/* Card Details */}
                    <HStack justify="space-between">
                      <Box flex={1}>
                        <Text fontSize="xs" opacity={0.8} mb={1}>
                          Card Holder
                        </Text>
                        <Text fontSize="sm" fontWeight="600" textTransform="uppercase">
                          {card.card_holder_name}
                        </Text>
                      </Box>
                      <Box>
                        <Text fontSize="xs" opacity={0.8} mb={1}>
                          Expires
                        </Text>
                        <Text fontSize="sm" fontWeight="600">
                          {card.expiry_month}/{card.expiry_year.toString().slice(-2)}
                        </Text>
                      </Box>
                      <Box>
                        <HStack>
                          <Text fontSize="xs" opacity={0.8}>
                            CVV
                          </Text>
                          <IconButton
                            aria-label="Toggle CVV"
                            icon={<Icon as={showCvv[card.card_id] ? FiEyeOff : FiEye} />}
                            size="xs"
                            variant="ghost"
                            color="white"
                            onClick={() => toggleCvv(card.card_id)}
                          />
                        </HStack>
                        <Text fontSize="sm" fontWeight="600">
                          {showCvv[card.card_id] && card.cvv ? card.cvv : '***'}
                        </Text>
                      </Box>
                    </HStack>

                    {/* Balance & Status */}
                    <HStack justify="space-between" pt={2} borderTop="1px" borderColor="whiteAlpha.300">
                      <Box>
                        <Text fontSize="xs" opacity={0.8}>
                          Balance
                        </Text>
                        <Text fontSize="lg" fontWeight="bold">
                          {formatCurrency(card.balance, card.currency)}
                        </Text>
                      </Box>
                      <Badge
                        colorScheme={card.status === 'active' ? 'green' : 'red'}
                        variant="solid"
                      >
                        {card.status}
                      </Badge>
                    </HStack>
                  </VStack>
                </Box>
              </Box>

                {/* Card Menu - Positioned outside overflow container */}
                <Box position="absolute" top={2} right={2} zIndex={10}>
                  <Menu placement="bottom-end">
                    <MenuButton
                      as={IconButton}
                      icon={<Icon as={FiMoreVertical} />}
                      variant="ghost"
                      size="sm"
                      color="white"
                      _hover={{ bg: 'whiteAlpha.200' }}
                    />
                    <MenuList color="gray.800" zIndex={1500}>
                      <MenuItem icon={<Icon as={FiDollarSign} />} onClick={() => openFundModal(card)}>
                        Fund Card
                      </MenuItem>
                      <MenuItem icon={<Icon as={FiShield} />} onClick={() => openControlsModal(card)}>
                        Card Controls
                      </MenuItem>
                      <MenuItem icon={<Icon as={FiEye} />} onClick={() => openDetailsModal(card)}>
                        View Details
                      </MenuItem>
                      {card.status === 'inactive' && (
                        <MenuItem
                          icon={<Icon as={FiUnlock} />}
                          onClick={() => handleActivate(card.card_id)}
                          color="green.500"
                        >
                          Activate Card
                        </MenuItem>
                      )}
                      {(card.status === 'active' || card.is_frozen) && (
                        <MenuItem
                          icon={<Icon as={card.is_frozen ? FiUnlock : FiLock} />}
                          onClick={() => handleFreeze(card.card_id, !card.is_frozen)}
                        >
                          {card.is_frozen ? 'Unfreeze Card' : 'Freeze Card'}
                        </MenuItem>
                      )}
                      <Divider />
                      {card.status !== 'blocked' && (
                        <MenuItem
                          icon={<Icon as={FiShield} />}
                          color="red.500"
                          onClick={() => handleBlock(card.card_id)}
                        >
                          Block Card Permanently
                        </MenuItem>
                      )}
                      <MenuItem
                        icon={<Icon as={FiTrash2} />}
                        color="red.500"
                        onClick={() => {
                          setDeleteCardId(card.card_id);
                          onDeleteOpen();
                        }}
                      >
                        Delete Card
                      </MenuItem>
                    </MenuList>
                  </Menu>
                </Box>
              </Box>
            ))}
          </SimpleGrid>
        ) : (
          <EmptyState
            icon={FiCreditCard}
            title="No cards yet"
            description="Create your first virtual card to start making online payments"
            actionLabel="Create Card"
            onAction={onCreateOpen}
          />
        )}
      </VStack>

      {/* Create Card Modal */}
      <Modal isOpen={isCreateOpen} onClose={onCreateClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={createForm.handleSubmit(handleCreate)}>
            <ModalHeader>Create New Card</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Select Wallet</FormLabel>
                  <Select {...createForm.register('wallet_id')} placeholder="Choose wallet">
                    {wallets.map((wallet: any) => (
                      <option key={wallet.wallet_id} value={wallet.wallet_id}>
                        {wallet.name} - {formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')}
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Currency</FormLabel>
                  <Select {...createForm.register('currency_code')} placeholder="Select currency">
                    {currencies.map((currency) => (
                      <option key={currency.code} value={currency.code}>
                        {currency.name} ({currency.code})
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Card Type</FormLabel>
                  <Select {...createForm.register('card_type')} placeholder="Select type">
                    <option value="virtual">Virtual Card</option>
                    <option value="physical">Physical Card</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Card Brand</FormLabel>
                  <Select {...createForm.register('card_brand')} placeholder="Select brand">
                    <option value="visa">Visa</option>
                    <option value="mastercard">Mastercard</option>
                    <option value="verve">Verve</option>
                  </Select>
                </FormControl>

                <FormControl>
                  <FormLabel>Card Nickname (Optional)</FormLabel>
                  <Input
                    {...createForm.register('nickname')}
                    placeholder="e.g., Netflix Card"
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onCreateClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={creating}>
                Create Card
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Fund Card Modal */}
      <Modal isOpen={isFundOpen} onClose={onFundClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={fundForm.handleSubmit(handleFund)}>
            <ModalHeader>Fund Card</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Amount</FormLabel>
                  <Input
                    type="number"
                    step="0.01"
                    {...fundForm.register('amount', { valueAsNumber: true })}
                    placeholder="Enter amount"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Wallet PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...fundForm.register('pin')}
                    placeholder="Enter your wallet PIN"
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onFundClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={funding}>
                Fund Card
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Card Controls Modal */}
      <Modal isOpen={isControlsOpen} onClose={onControlsClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Card Controls</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={6} align="stretch">
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiGlobe} />
                  <Box>
                    <Text fontWeight="600">International Transactions</Text>
                    <Text fontSize="sm" color="gray.600">
                      Allow payments outside your country
                    </Text>
                  </Box>
                </HStack>
                <Switch
                  isChecked={selectedCard?.allow_international_transactions}
                  onChange={(e) =>
                    handleControlToggle(selectedCard, 'allow_international_transactions', e.target.checked)
                  }
                />
              </HStack>

              <Divider />

              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiShoppingCart} />
                  <Box>
                    <Text fontWeight="600">Online Transactions</Text>
                    <Text fontSize="sm" color="gray.600">
                      Enable online shopping and payments
                    </Text>
                  </Box>
                </HStack>
                <Switch
                  isChecked={selectedCard?.allow_online_transactions}
                  onChange={(e) =>
                    handleControlToggle(selectedCard, 'allow_online_transactions', e.target.checked)
                  }
                />
              </HStack>

              <Divider />

              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiShield} />
                  <Box>
                    <Text fontWeight="600">ATM Withdrawals</Text>
                    <Text fontSize="sm" color="gray.600">
                      Allow cash withdrawals from ATMs
                    </Text>
                  </Box>
                </HStack>
                <Switch
                  isChecked={selectedCard?.allow_atm_withdrawals}
                  onChange={(e) =>
                    handleControlToggle(selectedCard, 'allow_atm_withdrawals', e.target.checked)
                  }
                />
              </HStack>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onControlsClose}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Card Details Modal */}
      <Modal isOpen={isDetailsOpen} onClose={onDetailsClose} size={{ base: "full", sm: "lg", md: "xl" }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Card Transactions</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <CardTransactions cardId={selectedCard?.id} />
          </ModalBody>
          <ModalFooter>
            <Button onClick={onDetailsClose}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Delete Confirmation */}
      <AlertDialog isOpen={isDeleteOpen} leastDestructiveRef={cancelRef} onClose={onDeleteClose}>
        <AlertDialogOverlay>
          <AlertDialogContent>
            <AlertDialogHeader>Delete Card</AlertDialogHeader>
            <AlertDialogBody>
              Are you sure you want to delete this card? This action cannot be undone.
            </AlertDialogBody>
            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onDeleteClose}>
                Cancel
              </Button>
              <Button colorScheme="red" onClick={handleDelete} ml={3} isLoading={deleting}>
                Delete
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>
    </Container>
  );
};

// Card Transactions Component
const CardTransactions = ({ cardId }: { cardId: string }) => {
  const { data, isLoading } = useGetCardTransactionsQuery(
    { cardId, params: { limit: 10 } },
    { skip: !cardId }
  );

  const transactions = data?.data || [];

  if (isLoading) {
    return (
      <Box textAlign="center" py={8}>
        <Text color="gray.500">Loading transactions...</Text>
      </Box>
    );
  }

  if (transactions.length === 0) {
    return (
      <EmptyState
        icon={FiCreditCard}
        title="No transactions yet"
        description="Transactions made with this card will appear here"
      />
    );
  }

  return (
    <Table variant="simple">
      <Thead>
        <Tr>
          <Th>Merchant</Th>
          <Th>Amount</Th>
          <Th>Status</Th>
          <Th>Date</Th>
        </Tr>
      </Thead>
      <Tbody>
        {transactions.map((txn: any) => (
          <Tr key={txn.id}>
            <Td>{txn.merchant_name || 'Unknown'}</Td>
            <Td fontWeight="600">{formatCurrency(txn.amount, txn.currency)}</Td>
            <Td>
              <Badge colorScheme={getStatusColor(txn.status)}>{txn.status}</Badge>
            </Td>
            <Td fontSize="sm" color="gray.600">
              {formatRelativeTime(txn.created_at)}
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
};
