import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  HStack,
  Card,
  CardBody,
  Icon,
  SimpleGrid,
  Button,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Link,
  Divider,
  Skeleton,
  SkeletonText,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  Input,
  IconButton,
  Flex,
  Avatar,
  useDisclosure,
} from '@chakra-ui/react';
import {
  FiMail,
  FiPhone,
  FiMessageCircle,
  FiBook,
  FiHelpCircle,
  FiExternalLink,
  FiSend,
  FiX,
} from 'react-icons/fi';
import {
  useListFAQsQuery,
  useCreateTicketMutation,
  useAddMessageMutation,
  useGetTicketMessagesQuery,
} from '@/features/support/services/supportApi';
import { useState, useRef, useEffect } from 'react';
import { useToast } from '@chakra-ui/react';

// Simple component to render markdown-like formatting
const FormattedText = ({ text }: { text: string }) => {
  const formatText = (content: string) => {
    // Split by lines
    const lines = content.split('\n');
    const elements: JSX.Element[] = [];

    lines.forEach((line, index) => {
      const trimmed = line.trim();

      if (!trimmed) {
        // Empty line
        elements.push(<Box key={index} h={2} />);
      } else if (trimmed.startsWith('**') && trimmed.endsWith('**')) {
        // Bold heading
        const text = trimmed.slice(2, -2);
        elements.push(
          <Text key={index} fontWeight="bold" mt={2} mb={1}>
            {text}
          </Text>
        );
      } else if (trimmed.startsWith('•')) {
        // Bullet point
        elements.push(
          <Text key={index} pl={4} fontSize="sm">
            {trimmed}
          </Text>
        );
      } else {
        // Regular text
        elements.push(
          <Text key={index} fontSize="sm">
            {trimmed}
          </Text>
        );
      }
    });

    return elements;
  };

  return <Box>{formatText(text)}</Box>;
};

export const SupportPage = () => {
  const toast = useToast();
  const { data: faqData, isLoading: loadingFAQs } = useListFAQsQuery();
  const faqs = faqData?.data || [];

  // Live Chat state
  const { isOpen: isChatOpen, onOpen: onChatOpen, onClose: onChatClose } = useDisclosure();
  const [activeTicketId, setActiveTicketId] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // API hooks
  const [createTicket, { isLoading: creatingTicket }] = useCreateTicketMutation();
  const [addMessage, { isLoading: sendingMessage }] = useAddMessageMutation();
  const { data: messagesData, refetch: refetchMessages } = useGetTicketMessagesQuery(
    { ticketId: activeTicketId!, params: { limit: 50 } },
    { skip: !activeTicketId, pollingInterval: 3000 } // Poll every 3 seconds for new messages
  );

  // Debug: Log messages data structure
  useEffect(() => {
    if (messagesData) {
      console.log('Messages Data:', messagesData);
      console.log('messagesData.data:', messagesData.data);
    }
  }, [messagesData]);

  // Backend returns messages in data.data (nested structure)
  const messages = (messagesData?.data as any)?.data || [];

  // Scroll to bottom when messages update
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleStartChat = async () => {
    try {
      const response = await createTicket({
        subject: 'Live Chat Support',
        category: 'other',
        priority: 'medium',
        description: 'User initiated live chat support',
      }).unwrap();

      console.log('Create Ticket Response:', response);
      console.log('Ticket ID:', response.data?.ticket_id || response.data?.id);

      // Backend returns ticket_id, not id
      const ticketId = response.data?.ticket_id || response.data?.id;
      setActiveTicketId(ticketId);
      onChatOpen();
    } catch (error: any) {
      console.error('Create ticket error:', error);
      toast({
        title: 'Failed to start chat',
        description: error?.data?.message || 'Please try again',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleSendMessage = async () => {
    console.log('Send button clicked!');
    console.log('Message:', message);
    console.log('Active Ticket ID:', activeTicketId);

    if (!message.trim() || !activeTicketId) {
      console.log('Validation failed - message or ticketId missing');
      return;
    }

    try {
      console.log('Sending message...');
      const result = await addMessage({
        ticketId: activeTicketId,
        data: { message: message.trim() },
      }).unwrap();

      console.log('Message sent successfully:', result);
      setMessage('');
      refetchMessages();

      toast({
        title: 'Message sent',
        status: 'success',
        duration: 2000,
      });
    } catch (error: any) {
      console.error('Send message error:', error);
      toast({
        title: 'Failed to send message',
        description: error?.data?.message || 'Please try again',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleCloseChat = () => {
    onChatClose();
    setActiveTicketId(null);
    setMessage('');
  };

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={8} align="stretch">
        {/* Header */}
        <Box>
          <Heading size="lg" mb={2}>
            Support Center
          </Heading>
          <Text color="gray.600">
            Get help and find answers to your questions
          </Text>
        </Box>

        {/* Contact Options */}
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6}>
          <Card>
            <CardBody>
              <VStack spacing={4} align="start">
                <Icon as={FiMail} boxSize={8} color="brand.500" />
                <Box>
                  <Heading size="sm" mb={1}>
                    Email Support
                  </Heading>
                  <Text fontSize="sm" color="gray.600" mb={2}>
                    Get help via email
                  </Text>
                  <Link
                    href="mailto:support@paycore.com"
                    color="brand.500"
                    fontSize="sm"
                  >
                    support@paycore.com
                  </Link>
                </Box>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={4} align="start">
                <Icon as={FiPhone} boxSize={8} color="brand.500" />
                <Box>
                  <Heading size="sm" mb={1}>
                    Phone Support
                  </Heading>
                  <Text fontSize="sm" color="gray.600" mb={2}>
                    Call us during business hours
                  </Text>
                  <Link href="tel:+2341234567890" color="brand.500" fontSize="sm">
                    +234 123 456 7890
                  </Link>
                </Box>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={4} align="start">
                <Icon as={FiMessageCircle} boxSize={8} color="brand.500" />
                <Box>
                  <Heading size="sm" mb={1}>
                    Live Chat
                  </Heading>
                  <Text fontSize="sm" color="gray.600" mb={2}>
                    Chat with our support team
                  </Text>
                  <Button
                    size="sm"
                    colorScheme="brand"
                    rightIcon={<FiMessageCircle />}
                    onClick={handleStartChat}
                    isLoading={creatingTicket}
                  >
                    Start Chat
                  </Button>
                </Box>
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        <Divider />

        {/* FAQs */}
        <Box>
          <HStack spacing={3} mb={6}>
            <Icon as={FiHelpCircle} boxSize={6} color="brand.500" />
            <Heading size="md">Frequently Asked Questions</Heading>
          </HStack>

          {loadingFAQs ? (
            <VStack spacing={4} align="stretch">
              {[1, 2, 3, 4].map((i) => (
                <Box key={i} p={4} borderWidth="1px" borderRadius="md">
                  <Skeleton height="20px" width="60%" mb={2} />
                  <SkeletonText noOfLines={2} spacing={2} />
                </Box>
              ))}
            </VStack>
          ) : faqs.length > 0 ? (
            <Accordion allowToggle>
              {faqs.map((faq: any) => (
                <AccordionItem key={faq.faq_id}>
                  <h2>
                    <AccordionButton py={4}>
                      <Box flex="1" textAlign="left" fontWeight="600">
                        {faq.question}
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4} color="gray.600">
                    <FormattedText text={faq.answer} />
                  </AccordionPanel>
                </AccordionItem>
              ))}
            </Accordion>
          ) : (
            <Card>
              <CardBody>
                <Text color="gray.600" textAlign="center">
                  No FAQs available at the moment.
                </Text>
              </CardBody>
            </Card>
          )}
        </Box>

        <Divider />

        {/* Resources */}
        <Box>
          <HStack spacing={3} mb={6}>
            <Icon as={FiBook} boxSize={6} color="brand.500" />
            <Heading size="md">Additional Resources</Heading>
          </HStack>

          <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
            <Card variant="outline">
              <CardBody>
                <HStack justify="space-between">
                  <Box>
                    <Heading size="sm" mb={1}>
                      User Guide
                    </Heading>
                    <Text fontSize="sm" color="gray.600">
                      Learn how to use all features
                    </Text>
                  </Box>
                  <Icon as={FiExternalLink} color="brand.500" />
                </HStack>
              </CardBody>
            </Card>

            <Card variant="outline">
              <CardBody>
                <HStack justify="space-between">
                  <Box>
                    <Heading size="sm" mb={1}>
                      API Documentation
                    </Heading>
                    <Text fontSize="sm" color="gray.600">
                      For developers and integrations
                    </Text>
                  </Box>
                  <Icon as={FiExternalLink} color="brand.500" />
                </HStack>
              </CardBody>
            </Card>

            <Card variant="outline">
              <CardBody>
                <HStack justify="space-between">
                  <Box>
                    <Heading size="sm" mb={1}>
                      Security & Privacy
                    </Heading>
                    <Text fontSize="sm" color="gray.600">
                      Learn about our security practices
                    </Text>
                  </Box>
                  <Icon as={FiExternalLink} color="brand.500" />
                </HStack>
              </CardBody>
            </Card>

            <Card variant="outline">
              <CardBody>
                <HStack justify="space-between">
                  <Box>
                    <Heading size="sm" mb={1}>
                      Terms of Service
                    </Heading>
                    <Text fontSize="sm" color="gray.600">
                      Read our terms and conditions
                    </Text>
                  </Box>
                  <Icon as={FiExternalLink} color="brand.500" />
                </HStack>
              </CardBody>
            </Card>
          </SimpleGrid>
        </Box>

        {/* Business Hours */}
        <Card bg="brand.50">
          <CardBody>
            <VStack align="start" spacing={2}>
              <Heading size="sm">Support Hours</Heading>
              <Text fontSize="sm" color="gray.600">
                Monday - Friday: 8:00 AM - 8:00 PM (WAT)
              </Text>
              <Text fontSize="sm" color="gray.600">
                Saturday - Sunday: 10:00 AM - 6:00 PM (WAT)
              </Text>
              <Text fontSize="sm" color="gray.500" fontStyle="italic">
                We aim to respond to all inquiries within 24 hours
              </Text>
            </VStack>
          </CardBody>
        </Card>
      </VStack>

      {/* Live Chat Modal */}
      <Modal isOpen={isChatOpen} onClose={handleCloseChat} size="lg">
        <ModalOverlay />
        <ModalContent maxH="600px">
          <ModalHeader>
            <HStack justify="space-between">
              <HStack>
                <Icon as={FiMessageCircle} color="brand.500" />
                <Text>Live Chat Support</Text>
              </HStack>
              <IconButton
                icon={<FiX />}
                aria-label="Close chat"
                size="sm"
                variant="ghost"
                onClick={handleCloseChat}
              />
            </HStack>
          </ModalHeader>
          <ModalBody pb={4}>
            <VStack align="stretch" spacing={4} height="400px">
              {/* Messages Container */}
              <Box
                flex="1"
                overflowY="auto"
                borderWidth="1px"
                borderRadius="md"
                p={4}
                bg="gray.50"
              >
                {messages.length === 0 ? (
                  <VStack spacing={2} py={8}>
                    <Icon as={FiMessageCircle} boxSize={12} color="gray.400" />
                    <Text color="gray.600">Start a conversation with our support team</Text>
                  </VStack>
                ) : (
                  <VStack align="stretch" spacing={3}>
                    {messages.map((msg: any) => {
                      // Backend uses is_from_customer instead of sender_type
                      const isCustomer = msg.is_from_customer;
                      return (
                        <Flex
                          key={msg.message_id || msg.id}
                          justify={isCustomer ? 'flex-end' : 'flex-start'}
                        >
                          <HStack
                            spacing={2}
                            maxW="70%"
                            flexDirection={isCustomer ? 'row-reverse' : 'row'}
                          >
                            <Avatar
                              size="sm"
                              name={msg.sender_email}
                              bg={isCustomer ? 'brand.500' : 'green.500'}
                            />
                            <Box
                              bg={isCustomer ? 'brand.500' : 'white'}
                              color={isCustomer ? 'white' : 'black'}
                              px={4}
                              py={2}
                              borderRadius="lg"
                              boxShadow="sm"
                            >
                              <Text fontSize="sm">{msg.message}</Text>
                              <Text
                                fontSize="xs"
                                opacity={0.7}
                                mt={1}
                              >
                                {new Date(msg.created_at).toLocaleTimeString()}
                              </Text>
                            </Box>
                          </HStack>
                        </Flex>
                      );
                    })}
                    <div ref={messagesEndRef} />
                  </VStack>
                )}
              </Box>

              {/* Message Input */}
              <HStack>
                <Input
                  placeholder="Type your message..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSendMessage();
                    }
                  }}
                  disabled={sendingMessage}
                />
                <IconButton
                  icon={<FiSend />}
                  aria-label="Send message"
                  colorScheme="brand"
                  onClick={handleSendMessage}
                  isLoading={sendingMessage}
                  isDisabled={!message.trim() || sendingMessage}
                />
              </HStack>
            </VStack>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Container>
  );
};
