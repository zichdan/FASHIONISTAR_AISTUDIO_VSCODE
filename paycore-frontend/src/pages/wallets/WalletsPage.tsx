import {
  Box,
  Container,
  Grid,
  GridItem,
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
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Switch,
  PinInput,
  PinInputField,
  Skeleton,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  IconButton,
  Divider,
} from '@chakra-ui/react';
import {
  FiPlus,
  FiMoreVertical,
  FiEdit,
  FiLock,
  FiUnlock,
  FiShield,
  FiStar,
  FiEye,
  FiEyeOff,
  FiRefreshCw,
  FiDollarSign,
} from 'react-icons/fi';
import { MdAccountBalanceWallet } from 'react-icons/md';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import {
  useListWalletsQuery,
  useListCurrenciesQuery,
  useCreateWalletMutation,
  useUpdateWalletMutation,
  useSetDefaultWalletMutation,
  useSetPinMutation,
  useChangePinMutation,
  useEnableWalletSecurityMutation,
  useDisableWalletSecurityMutation,
  useChangeWalletStatusMutation,
} from '@/features/wallets/services/walletsApi';
import { useInitiateDepositMutation } from '@/features/transactions/services/transactionsApi';
import { NumberInput, NumberInputField } from '@chakra-ui/react';
import { formatCurrency, formatRelativeTime, getStatusColor } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { KYCRequired } from '@/components/common/KYCRequired';
import { isKYCRequiredError } from '@/utils/errorHandlers';
import { EmptyState } from '@/components/common/EmptyState';

interface CreateWalletForm {
  name: string;
  currency: string;
  type: string;
}

interface PinForm {
  pin: string;
  confirm_pin: string;
  old_pin?: string;
}

export const WalletsPage = () => {
  const toast = useToast();

  // Helper function to format error messages
  const getErrorMessage = (error: any): string => {
    let errorMessage = error.data?.message || 'An error occurred';

    // Handle field-level validation errors for invalid_entry
    if (error.data?.code === 'invalid_entry' && error.data?.data) {
      const fieldErrors = Object.entries(error.data.data)
        .map(([field, message]) => `${field}: ${message}`)
        .join(', ');
      errorMessage = fieldErrors || errorMessage;
    }

    return errorMessage;
  };

  // State
  const [selectedWallet, setSelectedWallet] = useState<any>(null);
  const [pinAction, setPinAction] = useState<'set' | 'change' | null>(null);
  const [showBalance, setShowBalance] = useState(true);

  // Modals
  const { isOpen: isCreateOpen, onOpen: onCreateOpen, onClose: onCreateClose } = useDisclosure();
  const { isOpen: isEditOpen, onOpen: onEditOpen, onClose: onEditClose } = useDisclosure();
  const { isOpen: isPinOpen, onOpen: onPinOpen, onClose: onPinClose } = useDisclosure();
  const { isOpen: isSecurityOpen, onOpen: onSecurityOpen, onClose: onSecurityClose } = useDisclosure();
  const { isOpen: isFundOpen, onOpen: onFundOpen, onClose: onFundClose } = useDisclosure();

  // Forms
  const createForm = useForm<CreateWalletForm>();
  const editForm = useForm<CreateWalletForm>();
  const pinForm = useForm<PinForm>();
  const fundForm = useForm<{amount: number; payment_method: string}>();

  // API
  const { data: walletsData, isLoading, error, refetch } = useListWalletsQuery();
  const { data: currenciesData } = useListCurrenciesQuery();
  const [createWallet, { isLoading: creating }] = useCreateWalletMutation();
  const [updateWallet, { isLoading: updating }] = useUpdateWalletMutation();
  const [setDefaultWallet] = useSetDefaultWalletMutation();
  const [setPin, { isLoading: settingPin }] = useSetPinMutation();
  const [changePin, { isLoading: changingPin }] = useChangePinMutation();
  const [enableWalletSecurity] = useEnableWalletSecurityMutation();
  const [disableWalletSecurity] = useDisableWalletSecurityMutation();
  const [changeStatus] = useChangeWalletStatusMutation();
  const [initiateDeposit, { isLoading: depositing }] = useInitiateDepositMutation();

  const wallets = walletsData?.data || [];
  const currencies = currenciesData?.data || [];

  // Handlers
  const handleCreate = async (data: CreateWalletForm) => {
    try {
      await createWallet({
        name: data.name,
        currency_code: data.currency,
        wallet_type: data.type as 'main' | 'savings' | 'investment',
      }).unwrap();
      toast({
        title: 'Wallet created successfully',
        status: 'success',
        duration: 3000,
      });
      onCreateClose();
      createForm.reset();
    } catch (error: any) {
      toast({
        title: 'Failed to create wallet',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleEdit = async (data: CreateWalletForm) => {
    if (!selectedWallet) return;
    try {
      // Only send the name field as backend doesn't support changing currency or type
      await updateWallet({
        id: selectedWallet.wallet_id,
        data: { name: data.name }
      }).unwrap();
      toast({
        title: 'Wallet updated successfully',
        status: 'success',
        duration: 3000,
      });
      onEditClose();
      setSelectedWallet(null);
    } catch (error: any) {
      toast({
        title: 'Failed to update wallet',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleSetDefault = async (walletId: string) => {
    try {
      await setDefaultWallet(walletId).unwrap();
      // Manually refetch to ensure UI updates with latest default status
      await refetch();
      toast({
        title: 'Default wallet set successfully',
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to set default wallet',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handlePinSubmit = async (data: PinForm) => {
    if (!selectedWallet) return;

    if (data.pin !== data.confirm_pin) {
      toast({
        title: 'PINs do not match',
        status: 'error',
        duration: 3000,
      });
      return;
    }

    try {
      if (pinAction === 'set') {
        await setPin({
          walletId: selectedWallet.wallet_id,
          data: { pin: parseInt(data.pin, 10) },
        }).unwrap();
      } else {
        await changePin({
          walletId: selectedWallet.wallet_id,
          data: {
            current_pin: parseInt(data.old_pin!, 10),
            new_pin: parseInt(data.pin, 10)
          },
        }).unwrap();
      }
      toast({
        title: `PIN ${pinAction === 'set' ? 'set' : 'changed'} successfully`,
        status: 'success',
        duration: 3000,
      });

      onPinClose();
      pinForm.reset();
      setPinAction(null);
    } catch (error: any) {
      toast({
        title: `Failed to ${pinAction} PIN`,
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleToggleBiometric = async (walletId: string, enabled: boolean) => {
    // Check if the wallet has a PIN set
    if (!selectedWallet?.requires_pin) {
      toast({
        title: 'PIN Required',
        description: 'Please set a wallet PIN first before enabling biometric authentication',
        status: 'warning',
        duration: 5000,
      });
      return;
    }

    try {
      if (enabled) {
        // Enable biometric - no PIN needed as we just need to set the flag
        // User must already have biometrics enabled on their profile
        await enableWalletSecurity({
          walletId,
          data: { enable_biometric: true }
        }).unwrap();
      } else {
        // For disabling, verify current PIN
        const pinStr = prompt('Enter your 4-digit wallet PIN to disable biometric:');
        if (!pinStr) return;

        const currentPin = parseInt(pinStr, 10);
        if (isNaN(currentPin) || currentPin < 1000 || currentPin > 9999) {
          toast({
            title: 'Invalid PIN',
            description: 'PIN must be a 4-digit number',
            status: 'error',
            duration: 3000,
          });
          return;
        }

        await disableWalletSecurity({
          walletId,
          data: { current_pin: currentPin, disable_biometric: true }
        }).unwrap();
      }

      toast({
        title: `Biometric ${enabled ? 'enabled' : 'disabled'} successfully`,
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: `Failed to ${enabled ? 'enable' : 'disable'} biometric`,
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleFreezeWallet = async (walletId: string, freeze: boolean) => {
    try {
      await changeStatus({
        walletId,
        status: freeze ? 'frozen' : 'active',
      }).unwrap();
      toast({
        title: `Wallet ${freeze ? 'frozen' : 'unfrozen'} successfully`,
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: `Failed to ${freeze ? 'freeze' : 'unfreeze'} wallet`,
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  const openEditModal = (wallet: any) => {
    setSelectedWallet(wallet);
    editForm.reset({
      name: wallet.name,
      // Currency and type are display-only, not editable
    });
    onEditOpen();
  };

  const openPinModal = (wallet: any, action: 'set' | 'change') => {
    setSelectedWallet(wallet);
    setPinAction(action);
    pinForm.reset();
    onPinOpen();
  };

  const openSecurityModal = (wallet: any) => {
    setSelectedWallet(wallet);
    onSecurityOpen();
  };

  const openFundModal = (wallet: any) => {
    setSelectedWallet(wallet);
    fundForm.reset();
    onFundOpen();
  };

  const handleFundWallet = async (data: {amount: number; payment_method: string}) => {
    if (!selectedWallet) return;

    try {
      const response = await initiateDeposit({
        wallet_id: selectedWallet.wallet_id,
        amount: data.amount,
        payment_method: data.payment_method,
      }).unwrap();

      toast({
        title: 'Deposit initiated successfully',
        description: response.data?.payment_url
          ? 'Redirecting to payment gateway...'
          : 'Processing your deposit...',
        status: 'success',
        duration: 3000,
      });

      // If there's a payment URL, open it in a new tab
      if (response.data?.payment_url) {
        window.open(response.data.payment_url, '_blank');
      }

      onFundClose();
      fundForm.reset();

      // Refresh wallets after a short delay
      setTimeout(() => {
        refetch();
      }, 3000);
    } catch (error: any) {
      toast({
        title: 'Failed to initiate deposit',
        description: getErrorMessage(error),
        status: 'error',
        duration: 5000,
      });
    }
  };

  if (isLoading) {
    return (
      <Container maxW="container.xl" py={8}>
        <VStack spacing={6} align="stretch">
          <Skeleton height="60px" />
          <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="200px" borderRadius="xl" />
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
          description="To manage your wallets, you need to complete your KYC verification first."
        />
      );
    }

    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load wallets. Please try again." />
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
              My Wallets
            </Heading>
            <Text color="gray.600" fontSize={{ base: "sm", md: "md" }}>Manage your wallets and security settings</Text>
          </Box>
          <HStack>
            <IconButton
              aria-label="Toggle balance visibility"
              icon={<Icon as={showBalance ? FiEye : FiEyeOff} />}
              variant="ghost"
              size={{ base: "sm", md: "md" }}
              onClick={() => setShowBalance(!showBalance)}
            />
            <Button leftIcon={<Icon as={FiPlus} />} colorScheme="brand" onClick={onCreateOpen} size={{ base: "sm", md: "md" }}>
              <Box display={{ base: "none", sm: "block" }}>Create Wallet</Box>
              <Box display={{ base: "block", sm: "none" }}>Create</Box>
            </Button>
          </HStack>
        </Stack>

        {/* Wallets Grid */}
        {wallets.length > 0 ? (
          <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
            {wallets.map((wallet: any) => (
              <Card
                key={wallet.wallet_id}
                position="relative"
                overflow="hidden"
                transition="all 0.2s"
                _hover={{ shadow: 'lg', transform: 'translateY(-2px)' }}
              >
                {wallet.is_default && (
                  <Box
                    position="absolute"
                    top={2}
                    left={2}
                    bg="brand.500"
                    color="white"
                    px={2}
                    py={1}
                    borderRadius="md"
                    fontSize="xs"
                    fontWeight="600"
                  >
                    <Icon as={FiStar} mr={1} />
                    Default
                  </Box>
                )}

                <Box
                  position="absolute"
                  top={2}
                  right={2}
                  zIndex={1}
                >
                  <Menu>
                    <MenuButton
                      as={IconButton}
                      icon={<Icon as={FiMoreVertical} />}
                      variant="ghost"
                      size="sm"
                    />
                    <MenuList>
                      <MenuItem icon={<Icon as={FiDollarSign} />} onClick={() => openFundModal(wallet)}>
                        Fund Wallet
                      </MenuItem>
                      <MenuItem icon={<Icon as={FiEdit} />} onClick={() => openEditModal(wallet)}>
                        Edit
                      </MenuItem>
                      {!wallet.is_default && (
                        <MenuItem icon={<Icon as={FiStar} />} onClick={() => handleSetDefault(wallet.wallet_id)}>
                          Set as Default
                        </MenuItem>
                      )}
                      <MenuItem
                        icon={<Icon as={FiShield} />}
                        onClick={() => openSecurityModal(wallet)}
                      >
                        Security Settings
                      </MenuItem>
                      <MenuItem
                        icon={<Icon as={wallet.status === 'active' ? FiLock : FiUnlock} />}
                        onClick={() => handleFreezeWallet(wallet.wallet_id, wallet.status === 'active')}
                      >
                        {wallet.status === 'active' ? 'Freeze' : 'Unfreeze'}
                      </MenuItem>
                    </MenuList>
                  </Menu>
                </Box>

                <CardBody pt={12}>
                  <VStack align="stretch" spacing={4}>
                    <HStack>
                      <Icon as={MdAccountBalanceWallet} boxSize={6} color="brand.500" />
                      <VStack align="start" spacing={0} flex={1}>
                        <Text fontWeight="600" fontSize="lg">
                          {wallet.name}
                        </Text>
                        <Text fontSize="sm" color="gray.500" textTransform="uppercase">
                          {wallet.currency?.code || 'N/A'} • {wallet.wallet_type}
                        </Text>
                      </VStack>
                    </HStack>

                    <Box>
                      <Text fontSize="sm" color="gray.500" mb={1}>
                        Available Balance
                      </Text>
                      <Text fontSize="2xl" fontWeight="bold">
                        {showBalance
                          ? formatCurrency(wallet.available_balance, wallet.currency?.code || 'NGN')
                          : '••••••'}
                      </Text>
                    </Box>

                    <HStack justify="space-between" pt={2} borderTop="1px" borderColor="gray.100">
                      <Badge colorScheme={getStatusColor(wallet.status)}>{wallet.status}</Badge>
                      <Text fontSize="xs" color="gray.500">
                        {formatRelativeTime(wallet.created_at)}
                      </Text>
                    </HStack>
                  </VStack>
                </CardBody>
              </Card>
            ))}
          </SimpleGrid>
        ) : (
          <EmptyState
            icon={MdAccountBalanceWallet}
            title="No wallets yet"
            description="Create your first wallet to start managing your funds"
            actionLabel="Create Wallet"
            onAction={onCreateOpen}
          />
        )}
      </VStack>

      {/* Create Wallet Modal */}
      <Modal isOpen={isCreateOpen} onClose={onCreateClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={createForm.handleSubmit(handleCreate)}>
            <ModalHeader>Create New Wallet</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Wallet Name</FormLabel>
                  <Input {...createForm.register('name')} placeholder="e.g., Personal Wallet" />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Currency</FormLabel>
                  <Select {...createForm.register('currency')} placeholder="Select currency">
                    {currencies.map((currency) => (
                      <option key={currency.code} value={currency.code}>
                        {currency.name} ({currency.code})
                      </option>
                    ))}
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Wallet Type</FormLabel>
                  <Select {...createForm.register('type')} placeholder="Select type">
                    <option value="main">Main Wallet</option>
                    <option value="savings">Savings Wallet</option>
                    <option value="investment">Investment Wallet</option>
                  </Select>
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onCreateClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={creating}>
                Create Wallet
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Edit Wallet Modal */}
      <Modal isOpen={isEditOpen} onClose={onEditClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={editForm.handleSubmit(handleEdit)}>
            <ModalHeader>Edit Wallet</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Wallet Name</FormLabel>
                  <Input {...editForm.register('name')} placeholder="Enter wallet name" />
                </FormControl>

                <FormControl>
                  <FormLabel>Currency</FormLabel>
                  <Input value={selectedWallet?.currency?.code || ''} disabled bg="gray.50" />
                  <Text fontSize="xs" color="gray.500" mt={1}>
                    Currency cannot be changed after wallet creation
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>Wallet Type</FormLabel>
                  <Input
                    value={selectedWallet?.wallet_type?.charAt(0).toUpperCase() + selectedWallet?.wallet_type?.slice(1) || ''}
                    disabled
                    bg="gray.50"
                  />
                  <Text fontSize="xs" color="gray.500" mt={1}>
                    Wallet type cannot be changed after creation
                  </Text>
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onEditClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={updating}>
                Save Changes
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Fund Wallet Modal */}
      <Modal isOpen={isFundOpen} onClose={onFundClose} size={{ base: "full", sm: "md", md: "lg" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={fundForm.handleSubmit(handleFundWallet)}>
            <ModalHeader>Fund Wallet</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl>
                  <FormLabel>Wallet</FormLabel>
                  <Input
                    value={selectedWallet ? `${selectedWallet.name} (${selectedWallet.currency?.code || 'NGN'})` : ''}
                    isReadOnly
                    bg="gray.50"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Amount</FormLabel>
                  <NumberInput min={0}>
                    <NumberInputField
                      {...fundForm.register('amount', { valueAsNumber: true })}
                      placeholder="0.00"
                    />
                  </NumberInput>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Payment Method</FormLabel>
                  <Select {...fundForm.register('payment_method')} placeholder="Select payment method">
                    <option value="card">Card Payment</option>
                    <option value="bank_transfer">Bank Transfer</option>
                    <option value="ussd">USSD</option>
                  </Select>
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onFundClose} size={{ base: "sm", md: "md" }}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={depositing} size={{ base: "sm", md: "md" }}>
                Continue
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* Security Settings Modal */}
      <Modal isOpen={isSecurityOpen} onClose={onSecurityClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Security Settings</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={6} align="stretch">
              <Box>
                <HStack justify="space-between" mb={4}>
                  <Box>
                    <Text fontWeight="600">PIN Protection</Text>
                    <Text fontSize="sm" color="gray.600">
                      Secure your wallet with a PIN
                    </Text>
                  </Box>
                  {selectedWallet?.requires_pin && (
                    <Badge colorScheme="green">PIN Set</Badge>
                  )}
                </HStack>
                <HStack>
                  {!selectedWallet?.requires_pin ? (
                    <Button
                      size="sm"
                      variant="outline"
                      colorScheme="brand"
                      onClick={() => openPinModal(selectedWallet, 'set')}
                    >
                      Set PIN
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => openPinModal(selectedWallet, 'change')}
                    >
                      Change PIN
                    </Button>
                  )}
                </HStack>
              </Box>

              <Divider />

              <HStack justify="space-between">
                <Box>
                  <Text fontWeight="600">Biometric Authentication</Text>
                  <Text fontSize="sm" color="gray.600">
                    Use fingerprint or face recognition
                  </Text>
                </Box>
                <Switch
                  isChecked={selectedWallet?.requires_biometric || false}
                  isDisabled={!selectedWallet?.wallet_id || !selectedWallet?.requires_pin}
                  onChange={(e) => {
                    if (selectedWallet?.wallet_id) {
                      handleToggleBiometric(selectedWallet.wallet_id, e.target.checked);
                    }
                  }}
                />
              </HStack>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onSecurityClose}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* PIN Modal */}
      <Modal isOpen={isPinOpen} onClose={onPinClose} size={{ base: "full", sm: "md" }}>
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={pinForm.handleSubmit(handlePinSubmit)}>
            <ModalHeader>{pinAction === 'set' ? 'Set' : 'Change'} PIN</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                {pinAction === 'change' && (
                  <FormControl isRequired>
                    <FormLabel>Old PIN</FormLabel>
                    <Input
                      type="password"
                      maxLength={4}
                      {...pinForm.register('old_pin')}
                      placeholder="Enter old PIN"
                    />
                  </FormControl>
                )}

                <FormControl isRequired>
                  <FormLabel>New PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...pinForm.register('pin')}
                    placeholder="Enter 4-digit PIN"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Confirm PIN</FormLabel>
                  <Input
                    type="password"
                    maxLength={4}
                    {...pinForm.register('confirm_pin')}
                    placeholder="Re-enter PIN"
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onPinClose}>
                Cancel
              </Button>
              <Button
                colorScheme="brand"
                type="submit"
                isLoading={settingPin || changingPin}
              >
                {pinAction === 'set' ? 'Set PIN' : 'Change PIN'}
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

    </Container>
  );
};
