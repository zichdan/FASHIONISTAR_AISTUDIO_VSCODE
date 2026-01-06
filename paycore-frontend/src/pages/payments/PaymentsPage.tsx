import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Heading,
  Tab,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  VStack,
  Button,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  useDisclosure,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalCloseButton,
  ModalBody,
  ModalFooter,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  Select,
  useToast,
  HStack,
  Text,
  Icon,
  IconButton,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Stack,
  SimpleGrid,
  Card,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Switch,
  Divider,
  Code,
  InputGroup,
  InputLeftElement,
  InputRightElement,
  AlertDialog,
  AlertDialogBody,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogContent,
  AlertDialogOverlay,
} from '@chakra-ui/react';
import {
  FiPlus,
  FiMoreVertical,
  FiEdit,
  FiTrash2,
  FiCopy,
  FiExternalLink,
  FiDollarSign,
  FiFileText,
  FiLink,
  FiSearch,
  FiX,
} from 'react-icons/fi';
import {
  useListPaymentLinksQuery,
  useCreatePaymentLinkMutation,
  useUpdatePaymentLinkMutation,
  useDeletePaymentLinkMutation,
  useListInvoicesQuery,
  useCreateInvoiceMutation,
  useUpdateInvoiceMutation,
  useDeleteInvoiceMutation,
  useListPaymentsQuery,
} from '@/features/payments/services/paymentsApi';
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';
import type { PaymentLink, Invoice, Payment, InvoiceItem } from '@/features/payments/types';

export const PaymentsPage = () => {
  const toast = useToast();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const cancelRef = useRef<HTMLButtonElement>(null);

  // Search states
  const [linkSearch, setLinkSearch] = useState('');
  const [invoiceSearch, setInvoiceSearch] = useState('');
  const [paymentSearch, setPaymentSearch] = useState('');

  // Payment Link Modal
  const {
    isOpen: isLinkOpen,
    onOpen: onLinkOpen,
    onClose: onLinkClose,
  } = useDisclosure();
  const [editingLink, setEditingLink] = useState<PaymentLink | null>(null);

  // Invoice Modal
  const {
    isOpen: isInvoiceOpen,
    onOpen: onInvoiceOpen,
    onClose: onInvoiceClose,
  } = useDisclosure();
  const [editingInvoice, setEditingInvoice] = useState<Invoice | null>(null);

  // Delete confirmation modal
  const {
    isOpen: isDeleteOpen,
    onOpen: onDeleteOpen,
    onClose: onDeleteClose,
  } = useDisclosure();
  const [invoiceToDelete, setInvoiceToDelete] = useState<string | null>(null);

  // API Queries
  const { data: walletsData } = useListWalletsQuery();
  const { data: linksData, isLoading: linksLoading } = useListPaymentLinksQuery({ page: 1, limit: 50 });
  const { data: invoicesData, isLoading: invoicesLoading } = useListInvoicesQuery({ page: 1, limit: 50 });
  const { data: paymentsData, isLoading: paymentsLoading } = useListPaymentsQuery({ page: 1, limit: 50 });

  // Mutations
  const [createLink] = useCreatePaymentLinkMutation();
  const [updateLink] = useUpdatePaymentLinkMutation();
  const [deleteLink] = useDeletePaymentLinkMutation();
  const [createInvoice] = useCreateInvoiceMutation();
  const [updateInvoice] = useUpdateInvoiceMutation();
  const [deleteInvoice] = useDeleteInvoiceMutation();

  // Form States
  const [linkForm, setLinkForm] = useState({
    wallet_id: '',
    title: '',
    description: '',
    amount: '',
    is_amount_fixed: true,
    is_single_use: false,
    expires_at: '',
    redirect_url: '',
  });

  const [invoiceForm, setInvoiceForm] = useState({
    wallet_id: '',
    title: '',
    description: '',
    customer_name: '',
    customer_email: '',
    customer_phone: '',
    customer_address: '',
    items: [{ description: '', quantity: '1', unit_price: '' }] as any[],
    tax_amount: '0',
    discount_amount: '0',
    issue_date: '',
    due_date: '',
    notes: '',
  });

  const handleCreateLink = async () => {
    try {
      await createLink({
        ...linkForm,
        amount: linkForm.amount ? parseFloat(linkForm.amount) : undefined,
      }).unwrap();

      toast({
        title: 'Payment Link Created',
        description: 'Your payment link has been created successfully.',
        status: 'success',
        duration: 3000,
      });

      onLinkClose();
      resetLinkForm();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.data?.message || 'Failed to create payment link',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleUpdateLink = async () => {
    if (!editingLink) return;

    try {
      await updateLink({
        id: editingLink.link_id,
        data: {
          title: linkForm.title,
          description: linkForm.description,
          redirect_url: linkForm.redirect_url,
        },
      }).unwrap();

      toast({
        title: 'Payment Link Updated',
        status: 'success',
        duration: 3000,
      });

      onLinkClose();
      setEditingLink(null);
      resetLinkForm();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.data?.message || 'Failed to update payment link',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleDeleteLink = async (id: string) => {
    if (!confirm('Are you sure you want to delete this payment link?')) return;

    try {
      await deleteLink(id).unwrap();
      toast({
        title: 'Payment Link Deleted',
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.data?.message || 'Failed to delete payment link',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const handleCreateInvoice = async () => {
    try {
      const items = invoiceForm.items.map((item: any) => ({
        description: item.description,
        quantity: parseFloat(item.quantity),
        unit_price: parseFloat(item.unit_price),
      }));

      await createInvoice({
        wallet_id: invoiceForm.wallet_id,
        title: invoiceForm.title,
        description: invoiceForm.description || undefined,
        customer_name: invoiceForm.customer_name,
        customer_email: invoiceForm.customer_email,
        customer_phone: invoiceForm.customer_phone || undefined,
        customer_address: invoiceForm.customer_address || undefined,
        items,
        tax_amount: parseFloat(invoiceForm.tax_amount),
        discount_amount: parseFloat(invoiceForm.discount_amount),
        issue_date: invoiceForm.issue_date,
        due_date: invoiceForm.due_date,
        notes: invoiceForm.notes || undefined,
      }).unwrap();

      toast({
        title: 'Invoice Created',
        description: 'Your invoice has been created successfully.',
        status: 'success',
        duration: 3000,
      });

      onInvoiceClose();
      resetInvoiceForm();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.data?.message || 'Failed to create invoice',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const openDeleteConfirmation = (invoiceId: string) => {
    setInvoiceToDelete(invoiceId);
    onDeleteOpen();
  };

  const confirmDeleteInvoice = async () => {
    if (!invoiceToDelete) return;

    try {
      await deleteInvoice(invoiceToDelete).unwrap();
      toast({
        title: 'Invoice Deleted',
        description: 'The invoice has been successfully deleted.',
        status: 'success',
        duration: 3000,
      });
      onDeleteClose();
      setInvoiceToDelete(null);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.data?.message || 'Failed to delete invoice',
        status: 'error',
        duration: 5000,
      });
    }
  };

  const resetLinkForm = () => {
    setLinkForm({
      wallet_id: '',
      title: '',
      description: '',
      amount: '',
      is_amount_fixed: true,
      is_single_use: false,
      expires_at: '',
      redirect_url: '',
    });
  };

  const resetInvoiceForm = () => {
    setInvoiceForm({
      wallet_id: '',
      title: '',
      description: '',
      customer_name: '',
      customer_email: '',
      customer_phone: '',
      customer_address: '',
      items: [{ description: '', quantity: '1', unit_price: '' }],
      tax_amount: '0',
      discount_amount: '0',
      issue_date: '',
      due_date: '',
      notes: '',
    });
  };

  const openEditLink = (link: PaymentLink) => {
    setEditingLink(link);
    setLinkForm({
      wallet_id: link.wallet_id,
      title: link.title,
      description: link.description || '',
      amount: link.amount?.toString() || '',
      is_amount_fixed: true,
      is_single_use: false,
      expires_at: link.expires_at || '',
      redirect_url: link.redirect_url || '',
    });
    onLinkOpen();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: 'Copied to clipboard',
      status: 'success',
      duration: 2000,
    });
  };

  // Filter functions
  const filteredLinks = linksData?.data?.links?.filter((link: PaymentLink) =>
    link.title.toLowerCase().includes(linkSearch.toLowerCase()) ||
    link.description?.toLowerCase().includes(linkSearch.toLowerCase()) ||
    link.slug.toLowerCase().includes(linkSearch.toLowerCase())
  ) || [];

  const filteredInvoices = invoicesData?.data?.data?.filter((invoice: Invoice) =>
    invoice.invoice_number.toLowerCase().includes(invoiceSearch.toLowerCase()) ||
    invoice.customer_name.toLowerCase().includes(invoiceSearch.toLowerCase()) ||
    invoice.customer_email.toLowerCase().includes(invoiceSearch.toLowerCase())
  ) || [];

  const filteredPayments = paymentsData?.data?.data?.filter((payment: Payment) =>
    payment.reference.toLowerCase().includes(paymentSearch.toLowerCase()) ||
    payment.payer_name.toLowerCase().includes(paymentSearch.toLowerCase()) ||
    payment.payer_email.toLowerCase().includes(paymentSearch.toLowerCase())
  ) || [];

  const addInvoiceItem = () => {
    setInvoiceForm({
      ...invoiceForm,
      items: [...invoiceForm.items, { description: '', quantity: '1', unit_price: '' }],
    });
  };

  const removeInvoiceItem = (index: number) => {
    setInvoiceForm({
      ...invoiceForm,
      items: invoiceForm.items.filter((_, i) => i !== index),
    });
  };

  const updateInvoiceItem = (index: number, field: string, value: string) => {
    const newItems = [...invoiceForm.items];
    newItems[index][field] = value;
    setInvoiceForm({ ...invoiceForm, items: newItems });
  };

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      active: 'green',
      inactive: 'gray',
      expired: 'red',
      draft: 'gray',
      sent: 'blue',
      paid: 'green',
      overdue: 'red',
      cancelled: 'red',
      completed: 'green',
      pending: 'yellow',
      failed: 'red',
    };
    return colors[status] || 'gray';
  };

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }} px={{ base: 4, md: 6 }}>
      <VStack spacing={{ base: 6, md: 8 }} align="stretch">
        {/* Header */}
        <Stack direction={{ base: 'column', md: 'row' }} justify="space-between" align={{ base: 'stretch', md: 'center' }} spacing={{ base: 4, md: 0 }}>
          <Heading size={{ base: 'md', md: 'lg' }}>Payments</Heading>
        </Stack>

        {/* Tabs */}
        <Tabs index={selectedTab} onChange={setSelectedTab} colorScheme="brand" size={{ base: 'sm', md: 'md' }}>
          <TabList overflowX="auto" overflowY="hidden">
            <Tab whiteSpace="nowrap">
              <HStack spacing={2}>
                <FiLink />
                <Text display={{ base: 'none', sm: 'block' }}>Payment Links</Text>
                <Text display={{ base: 'block', sm: 'none' }}>Links</Text>
              </HStack>
            </Tab>
            <Tab whiteSpace="nowrap">
              <HStack spacing={2}>
                <FiFileText />
                <Text>Invoices</Text>
              </HStack>
            </Tab>
            <Tab whiteSpace="nowrap">
              <HStack spacing={2}>
                <FiDollarSign />
                <Text display={{ base: 'none', sm: 'block' }}>Payment History</Text>
                <Text display={{ base: 'block', sm: 'none' }}>History</Text>
              </HStack>
            </Tab>
          </TabList>

          <TabPanels>
            {/* Payment Links Tab */}
            <TabPanel px={0}>
              <VStack spacing={6} align="stretch">
                <HStack justify="space-between">
                  <InputGroup maxW={{ base: 'full', md: '300px' }} size={{ base: 'sm', md: 'md' }}>
                    <InputLeftElement pointerEvents="none">
                      <Icon as={FiSearch} color="gray.400" />
                    </InputLeftElement>
                    <Input
                      placeholder="Search links..."
                      value={linkSearch}
                      onChange={(e) => setLinkSearch(e.target.value)}
                    />
                    {linkSearch && (
                      <InputRightElement>
                        <IconButton
                          aria-label="Clear search"
                          icon={<FiX />}
                          size="xs"
                          variant="ghost"
                          onClick={() => setLinkSearch('')}
                        />
                      </InputRightElement>
                    )}
                  </InputGroup>
                  <Button
                    leftIcon={<FiPlus />}
                    colorScheme="brand"
                    onClick={() => {
                      setEditingLink(null);
                      resetLinkForm();
                      onLinkOpen();
                    }}
                    size={{ base: 'sm', md: 'md' }}
                  >
                    <Box display={{ base: 'none', sm: 'block' }}>Create Link</Box>
                    <Box display={{ base: 'block', sm: 'none' }}>Create</Box>
                  </Button>
                </HStack>

                <Box overflowX="auto">
                  <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
                    <Thead>
                      <Tr>
                        <Th>Title</Th>
                        <Th display={{ base: 'none', lg: 'table-cell' }}>Amount</Th>
                        <Th display={{ base: 'none', md: 'table-cell' }}>Status</Th>
                        <Th display={{ base: 'none', lg: 'table-cell' }}>Uses</Th>
                        <Th>Actions</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {filteredLinks.map((link: PaymentLink) => (
                        <Tr key={link.link_id}>
                          <Td>
                            <VStack align="start" spacing={0}>
                              <Text fontWeight="medium" fontSize={{ base: 'xs', md: 'sm' }}>
                                {link.title}
                              </Text>
                              <Badge colorScheme={getStatusColor(link.status)} display={{ base: 'inline-flex', md: 'none' }} fontSize="2xs">
                                {link.status}
                              </Badge>
                            </VStack>
                          </Td>
                          <Td display={{ base: 'none', lg: 'table-cell' }}>
                            {link.amount ? parseFloat(link.amount).toLocaleString() : 'Flexible'}
                          </Td>
                          <Td display={{ base: 'none', md: 'table-cell' }}>
                            <Badge colorScheme={getStatusColor(link.status)}>{link.status}</Badge>
                          </Td>
                          <Td display={{ base: 'none', lg: 'table-cell' }}>
                            {link.payments_count || 0} {link.is_single_use ? '/ 1' : ''}
                          </Td>
                          <Td>
                            <Menu>
                              <MenuButton
                                as={IconButton}
                                icon={<FiMoreVertical />}
                                variant="ghost"
                                size="sm"
                              />
                              <MenuList>
                                <MenuItem icon={<FiCopy />} onClick={() => copyToClipboard(`${window.location.origin}/pay/${link.slug}`)}>
                                  Copy Link
                                </MenuItem>
                                <MenuItem icon={<FiExternalLink />} onClick={() => navigate(`/pay/${link.slug}`)}>
                                  View Payment Page
                                </MenuItem>
                                <MenuItem icon={<FiEdit />} onClick={() => openEditLink(link)}>
                                  Edit
                                </MenuItem>
                                <MenuItem icon={<FiTrash2 />} color="red.500" onClick={() => handleDeleteLink(link.link_id)}>
                                  Delete
                                </MenuItem>
                              </MenuList>
                            </Menu>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </Box>

                {!linksLoading && filteredLinks.length === 0 && (
                  <Box textAlign="center" py={10}>
                    <Text color="gray.500">
                      {linkSearch ? 'No payment links found matching your search.' : 'No payment links yet. Create one to get started.'}
                    </Text>
                  </Box>
                )}
              </VStack>
            </TabPanel>

            {/* Invoices Tab */}
            <TabPanel px={0}>
              <VStack spacing={6} align="stretch">
                <HStack justify="space-between">
                  <InputGroup maxW={{ base: 'full', md: '300px' }} size={{ base: 'sm', md: 'md' }}>
                    <InputLeftElement pointerEvents="none">
                      <Icon as={FiSearch} color="gray.400" />
                    </InputLeftElement>
                    <Input
                      placeholder="Search invoices..."
                      value={invoiceSearch}
                      onChange={(e) => setInvoiceSearch(e.target.value)}
                    />
                    {invoiceSearch && (
                      <InputRightElement>
                        <IconButton
                          aria-label="Clear search"
                          icon={<FiX />}
                          size="xs"
                          variant="ghost"
                          onClick={() => setInvoiceSearch('')}
                        />
                      </InputRightElement>
                    )}
                  </InputGroup>
                  <Button
                    leftIcon={<FiPlus />}
                    colorScheme="brand"
                    onClick={() => {
                      setEditingInvoice(null);
                      resetInvoiceForm();
                      onInvoiceOpen();
                    }}
                    size={{ base: 'sm', md: 'md' }}
                  >
                    <Box display={{ base: 'none', sm: 'block' }}>Create Invoice</Box>
                    <Box display={{ base: 'block', sm: 'none' }}>Create</Box>
                  </Button>
                </HStack>

                <Box overflowX="auto">
                  <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
                    <Thead>
                      <Tr>
                        <Th>Invoice #</Th>
                        <Th display={{ base: 'none', md: 'table-cell' }}>Customer</Th>
                        <Th>Amount</Th>
                        <Th display={{ base: 'none', lg: 'table-cell' }}>Status</Th>
                        <Th display={{ base: 'none', md: 'table-cell' }}>Due Date</Th>
                        <Th>Actions</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {filteredInvoices.map((invoice: Invoice) => (
                        <Tr key={invoice.invoice_id}>
                          <Td>
                            <VStack align="start" spacing={0}>
                              <Text fontWeight="medium" fontSize={{ base: 'xs', md: 'sm' }}>
                                {invoice.invoice_number}
                              </Text>
                              <Badge colorScheme={getStatusColor(invoice.status)} display={{ base: 'inline-flex', lg: 'none' }} fontSize="2xs">
                                {invoice.status}
                              </Badge>
                            </VStack>
                          </Td>
                          <Td display={{ base: 'none', md: 'table-cell' }}>{invoice.customer_name}</Td>
                          <Td>
                            <Text fontWeight="semibold" fontSize={{ base: 'xs', md: 'sm' }}>
                              {invoice.currency_code} {invoice.total_amount.toLocaleString()}
                            </Text>
                          </Td>
                          <Td display={{ base: 'none', lg: 'table-cell' }}>
                            <Badge colorScheme={getStatusColor(invoice.status)}>{invoice.status}</Badge>
                          </Td>
                          <Td display={{ base: 'none', md: 'table-cell' }}>
                            {new Date(invoice.due_date).toLocaleDateString()}
                          </Td>
                          <Td>
                            <Menu>
                              <MenuButton
                                as={IconButton}
                                icon={<FiMoreVertical />}
                                variant="ghost"
                                size="sm"
                              />
                              <MenuList>
                                <MenuItem icon={<FiExternalLink />} onClick={() => window.open(`${window.location.origin}/invoice/${invoice.invoice_id}`, '_blank')}>
                                  View Invoice
                                </MenuItem>
                                <MenuItem icon={<FiCopy />} onClick={() => {
                                  navigator.clipboard.writeText(`${window.location.origin}/invoice/${invoice.invoice_id}`);
                                  toast({ title: 'Link Copied', status: 'success', duration: 2000 });
                                }}>
                                  Copy Link
                                </MenuItem>
                                <MenuItem icon={<FiTrash2 />} color="red.500" onClick={() => openDeleteConfirmation(invoice.invoice_id)}>
                                  Delete
                                </MenuItem>
                              </MenuList>
                            </Menu>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </Box>

                {!invoicesLoading && filteredInvoices.length === 0 && (
                  <Box textAlign="center" py={10}>
                    <Text color="gray.500">
                      {invoiceSearch ? 'No invoices found matching your search.' : 'No invoices yet. Create one to get started.'}
                    </Text>
                  </Box>
                )}
              </VStack>
            </TabPanel>

            {/* Payment History Tab */}
            <TabPanel px={0}>
              <VStack spacing={6} align="stretch">
                <InputGroup maxW={{ base: 'full', md: '300px' }} size={{ base: 'sm', md: 'md' }}>
                  <InputLeftElement pointerEvents="none">
                    <Icon as={FiSearch} color="gray.400" />
                  </InputLeftElement>
                  <Input
                    placeholder="Search payments..."
                    value={paymentSearch}
                    onChange={(e) => setPaymentSearch(e.target.value)}
                  />
                  {paymentSearch && (
                    <InputRightElement>
                      <IconButton
                        aria-label="Clear search"
                        icon={<FiX />}
                        size="xs"
                        variant="ghost"
                        onClick={() => setPaymentSearch('')}
                      />
                    </InputRightElement>
                  )}
                </InputGroup>

                <Box overflowX="auto">
                  <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
                    <Thead>
                      <Tr>
                        <Th>Reference</Th>
                        <Th display={{ base: 'none', md: 'table-cell' }}>Payer</Th>
                        <Th>Amount</Th>
                        <Th display={{ base: 'none', lg: 'table-cell' }}>Status</Th>
                        <Th display={{ base: 'none', md: 'table-cell' }}>Date</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {filteredPayments.map((payment: Payment) => (
                        <Tr key={payment.payment_id}>
                          <Td>
                            <VStack align="start" spacing={0}>
                              <Text fontWeight="medium" fontSize={{ base: 'xs', md: 'sm' }}>
                                {payment.reference}
                              </Text>
                              <Badge colorScheme={getStatusColor(payment.status)} display={{ base: 'inline-flex', lg: 'none' }} fontSize="2xs">
                                {payment.status}
                              </Badge>
                            </VStack>
                          </Td>
                          <Td display={{ base: 'none', md: 'table-cell' }}>
                            <VStack align="start" spacing={0}>
                              <Text fontSize="sm">{payment.payer_name}</Text>
                              <Text fontSize="xs" color="gray.500">{payment.payer_email}</Text>
                            </VStack>
                          </Td>
                          <Td>
                            <Text fontWeight="semibold" fontSize={{ base: 'xs', md: 'sm' }}>
                              {payment.currency_code} {payment.amount.toLocaleString()}
                            </Text>
                          </Td>
                          <Td display={{ base: 'none', lg: 'table-cell' }}>
                            <Badge colorScheme={getStatusColor(payment.status)}>{payment.status}</Badge>
                          </Td>
                          <Td display={{ base: 'none', md: 'table-cell' }}>
                            {new Date(payment.created_at).toLocaleDateString()}
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </Box>

                {!paymentsLoading && filteredPayments.length === 0 && (
                  <Box textAlign="center" py={10}>
                    <Text color="gray.500">
                      {paymentSearch ? 'No payments found matching your search.' : 'No payments received yet.'}
                    </Text>
                  </Box>
                )}
              </VStack>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>

      {/* Create/Edit Payment Link Modal */}
      <Modal isOpen={isLinkOpen} onClose={onLinkClose} size={{ base: 'full', sm: 'md', md: 'lg' }}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{editingLink ? 'Edit Payment Link' : 'Create Payment Link'}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl isRequired>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Wallet</FormLabel>
                <Select
                  value={linkForm.wallet_id}
                  onChange={(e) => setLinkForm({ ...linkForm, wallet_id: e.target.value })}
                  placeholder="Select wallet"
                  isDisabled={!!editingLink}
                  size={{ base: 'sm', md: 'md' }}
                >
                  {walletsData?.data?.map((wallet: any) => (
                    <option key={wallet.wallet_id} value={wallet.wallet_id}>
                      {wallet.currency.code} - {wallet.currency.name}
                    </option>
                  ))}
                </Select>
              </FormControl>

              <FormControl isRequired>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Title</FormLabel>
                <Input
                  value={linkForm.title}
                  onChange={(e) => setLinkForm({ ...linkForm, title: e.target.value })}
                  placeholder="e.g., Freelance Invoice Payment"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Description</FormLabel>
                <Textarea
                  value={linkForm.description}
                  onChange={(e) => setLinkForm({ ...linkForm, description: e.target.value })}
                  placeholder="Payment for web design services"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Amount</FormLabel>
                <Input
                  type="number"
                  value={linkForm.amount}
                  onChange={(e) => setLinkForm({ ...linkForm, amount: e.target.value })}
                  placeholder="0.00"
                  isDisabled={!!editingLink}
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb={0} fontSize={{ base: 'sm', md: 'md' }}>Single Use Only</FormLabel>
                <Switch
                  isChecked={linkForm.is_single_use}
                  onChange={(e) => setLinkForm({ ...linkForm, is_single_use: e.target.checked })}
                  isDisabled={!!editingLink}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Expires At (Optional)</FormLabel>
                <Input
                  type="datetime-local"
                  value={linkForm.expires_at}
                  onChange={(e) => setLinkForm({ ...linkForm, expires_at: e.target.value })}
                  isDisabled={!!editingLink}
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Redirect URL (Optional)</FormLabel>
                <Input
                  value={linkForm.redirect_url}
                  onChange={(e) => setLinkForm({ ...linkForm, redirect_url: e.target.value })}
                  placeholder="https://yoursite.com/thank-you"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onLinkClose} size={{ base: 'sm', md: 'md' }}>
              Cancel
            </Button>
            <Button
              colorScheme="brand"
              onClick={editingLink ? handleUpdateLink : handleCreateLink}
              size={{ base: 'sm', md: 'md' }}
            >
              {editingLink ? 'Update' : 'Create'}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Create Invoice Modal */}
      <Modal isOpen={isInvoiceOpen} onClose={onInvoiceClose} size={{ base: 'full', md: 'xl' }} scrollBehavior="inside">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Create Invoice</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <FormControl isRequired>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Wallet</FormLabel>
                <Select
                  value={invoiceForm.wallet_id}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, wallet_id: e.target.value })}
                  placeholder="Select wallet"
                  size={{ base: 'sm', md: 'md' }}
                >
                  {walletsData?.data?.map((wallet: any) => (
                    <option key={wallet.wallet_id} value={wallet.wallet_id}>
                      {wallet.currency.code} - {wallet.currency.name}
                    </option>
                  ))}
                </Select>
              </FormControl>

              <Divider />

              <Heading size="sm">Invoice Details</Heading>

              <FormControl isRequired>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Invoice Title</FormLabel>
                <Input
                  value={invoiceForm.title}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, title: e.target.value })}
                  placeholder="Web Design Services"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Description</FormLabel>
                <Textarea
                  value={invoiceForm.description}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, description: e.target.value })}
                  placeholder="Additional invoice details..."
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Issue Date</FormLabel>
                  <Input
                    type="date"
                    value={invoiceForm.issue_date}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, issue_date: e.target.value })}
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Due Date</FormLabel>
                  <Input
                    type="date"
                    value={invoiceForm.due_date}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, due_date: e.target.value })}
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>
              </SimpleGrid>

              <Divider />

              <Heading size="sm">Customer Information</Heading>

              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Customer Name</FormLabel>
                  <Input
                    value={invoiceForm.customer_name}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, customer_name: e.target.value })}
                    placeholder="John Doe"
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Customer Email</FormLabel>
                  <Input
                    type="email"
                    value={invoiceForm.customer_email}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, customer_email: e.target.value })}
                    placeholder="john@example.com"
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>
              </SimpleGrid>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Phone</FormLabel>
                <Input
                  value={invoiceForm.customer_phone}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, customer_phone: e.target.value })}
                  placeholder="+2348012345678"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Address</FormLabel>
                <Textarea
                  value={invoiceForm.customer_address}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, customer_address: e.target.value })}
                  placeholder="Customer address"
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>

              <Divider />

              <HStack justify="space-between">
                <Heading size="sm">Invoice Items</Heading>
                <Button size="sm" leftIcon={<FiPlus />} onClick={addInvoiceItem}>
                  Add Item
                </Button>
              </HStack>

              {invoiceForm.items.map((item, index) => (
                <Card key={index} size="sm">
                  <CardBody>
                    <VStack spacing={3}>
                      <HStack width="full" justify="space-between">
                        <Text fontWeight="medium" fontSize={{ base: 'sm', md: 'md' }}>Item {index + 1}</Text>
                        {invoiceForm.items.length > 1 && (
                          <IconButton
                            size="xs"
                            icon={<FiTrash2 />}
                            aria-label="Remove item"
                            colorScheme="red"
                            variant="ghost"
                            onClick={() => removeInvoiceItem(index)}
                          />
                        )}
                      </HStack>
                      <FormControl isRequired>
                        <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Description</FormLabel>
                        <Input
                          value={item.description}
                          onChange={(e) => updateInvoiceItem(index, 'description', e.target.value)}
                          placeholder="Web Design Services"
                          size={{ base: 'sm', md: 'md' }}
                        />
                      </FormControl>
                      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3} width="full">
                        <FormControl isRequired>
                          <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Quantity</FormLabel>
                          <Input
                            type="number"
                            value={item.quantity}
                            onChange={(e) => updateInvoiceItem(index, 'quantity', e.target.value)}
                            min="1"
                            size={{ base: 'sm', md: 'md' }}
                          />
                        </FormControl>
                        <FormControl isRequired>
                          <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Unit Price</FormLabel>
                          <Input
                            type="number"
                            value={item.unit_price}
                            onChange={(e) => updateInvoiceItem(index, 'unit_price', e.target.value)}
                            placeholder="0.00"
                            size={{ base: 'sm', md: 'md' }}
                          />
                        </FormControl>
                      </SimpleGrid>
                    </VStack>
                  </CardBody>
                </Card>
              ))}

              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Tax Amount</FormLabel>
                  <Input
                    type="number"
                    value={invoiceForm.tax_amount}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, tax_amount: e.target.value })}
                    placeholder="0.00"
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>

                <FormControl>
                  <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Discount Amount</FormLabel>
                  <Input
                    type="number"
                    value={invoiceForm.discount_amount}
                    onChange={(e) => setInvoiceForm({ ...invoiceForm, discount_amount: e.target.value })}
                    placeholder="0.00"
                    size={{ base: 'sm', md: 'md' }}
                  />
                </FormControl>
              </SimpleGrid>

              <FormControl>
                <FormLabel fontSize={{ base: 'sm', md: 'md' }}>Notes</FormLabel>
                <Textarea
                  value={invoiceForm.notes}
                  onChange={(e) => setInvoiceForm({ ...invoiceForm, notes: e.target.value })}
                  placeholder="Payment terms, additional notes, etc."
                  size={{ base: 'sm', md: 'md' }}
                />
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onInvoiceClose} size={{ base: 'sm', md: 'md' }}>
              Cancel
            </Button>
            <Button colorScheme="brand" onClick={handleCreateInvoice} size={{ base: 'sm', md: 'md' }}>
              Create Invoice
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <AlertDialog
        isOpen={isDeleteOpen}
        leastDestructiveRef={cancelRef}
        onClose={onDeleteClose}
      >
        <AlertDialogOverlay>
          <AlertDialogContent>
            <AlertDialogHeader fontSize="lg" fontWeight="bold">
              Delete Invoice
            </AlertDialogHeader>

            <AlertDialogBody>
              Are you sure you want to delete this invoice? This action cannot be undone.
            </AlertDialogBody>

            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onDeleteClose}>
                Cancel
              </Button>
              <Button colorScheme="red" onClick={confirmDeleteInvoice} ml={3}>
                Delete
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>
    </Container>
  );
};

export default PaymentsPage;
