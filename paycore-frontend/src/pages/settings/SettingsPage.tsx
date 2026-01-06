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
  Icon,
  Switch,
  useToast,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Divider,
  Badge,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@chakra-ui/react';
import {
  FiShield,
  FiBell,
  FiMonitor,
  FiLock,
  FiMail,
  FiSmartphone,
} from 'react-icons/fi';
import { useState } from 'react';
import { useLogoutMutation } from '@/features/auth/services/authApi';
import { formatRelativeTime } from '@/utils/formatters';

export const SettingsPage = () => {
  const toast = useToast();

  // State
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [pushNotifications, setPushNotifications] = useState(true);

  // API
  const [logout] = useLogoutMutation();

  // Mock data for devices
  const devices = [
    {
      id: '1',
      device_name: 'Chrome on MacBook Pro',
      last_active: new Date().toISOString(),
      location: 'Lagos, Nigeria',
      is_current: true,
    },
    {
      id: '2',
      device_name: 'Safari on iPhone 14',
      last_active: new Date(Date.now() - 86400000).toISOString(),
      location: 'Lagos, Nigeria',
      is_current: false,
    },
  ];

  // Handlers
  const handleLogoutDevice = async (deviceId: string) => {
    try {
      // Call logout device API
      toast({
        title: 'Device logged out',
        status: 'success',
        duration: 3000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to logout device',
        status: 'error',
      });
    }
  };

  return (
    <Container maxW="container.xl" py={{ base: 4, md: 8 }}>
      <VStack spacing={{ base: 4, md: 8 }} align="stretch">
        {/* Header */}
        <Box>
          <Heading size={{ base: 'md', md: 'lg' }} mb={2}>
            Settings
          </Heading>
          <Text fontSize={{ base: 'sm', md: 'md' }} color="gray.600">Manage your account settings and preferences</Text>
        </Box>

        <Tabs>
          <TabList>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Security</Tab>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Notifications</Tab>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Devices</Tab>
            <Tab fontSize={{ base: 'sm', md: 'md' }}>Account</Tab>
          </TabList>

          <TabPanels>
            {/* Security Tab */}
            <TabPanel px={0}>
              <VStack spacing={{ base: 4, md: 6 }} align="stretch">
                <Card>
                  <CardBody>
                    <VStack align="stretch" spacing={{ base: 4, md: 6 }}>
                      {/* Session Management */}
                      <Stack direction={{ base: 'column', sm: 'row' }} justify="space-between" align={{ base: 'start', sm: 'center' }} spacing={{ base: 3, sm: 0 }}>
                        <HStack spacing={{ base: 2, md: 3 }}>
                          <Icon as={FiLock} boxSize={{ base: 4, md: 5 }} color="brand.500" />
                          <Box>
                            <Text fontWeight="600" fontSize={{ base: 'sm', md: 'md' }}>Session Timeout</Text>
                            <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600">
                              Automatically logout after 30 minutes of inactivity
                            </Text>
                          </Box>
                        </HStack>
                        <Switch colorScheme="brand" defaultChecked size={{ base: 'sm', md: 'md' }} />
                      </Stack>
                    </VStack>
                  </CardBody>
                </Card>
              </VStack>
            </TabPanel>

            {/* Notifications Tab */}
            <TabPanel px={0}>
              <VStack spacing={{ base: 4, md: 6 }} align="stretch">
                <Card>
                  <CardBody>
                    <VStack align="stretch" spacing={{ base: 4, md: 6 }}>
                      <Box>
                        <Heading size={{ base: 'xs', md: 'sm' }} mb={4}>
                          Notification Channels
                        </Heading>
                        <VStack align="stretch" spacing={{ base: 3, md: 4 }}>
                          <Stack direction={{ base: 'row' }} justify="space-between" align="center">
                            <HStack spacing={{ base: 2, md: 3 }}>
                              <Icon as={FiMail} color="gray.500" boxSize={{ base: 4, md: 5 }} />
                              <Text fontSize={{ base: 'sm', md: 'md' }}>Email Notifications</Text>
                            </HStack>
                            <Switch
                              colorScheme="brand"
                              size={{ base: 'sm', md: 'md' }}
                              isChecked={emailNotifications}
                              onChange={(e) => setEmailNotifications(e.target.checked)}
                            />
                          </Stack>
                          <Stack direction={{ base: 'row' }} justify="space-between" align="center">
                            <HStack spacing={{ base: 2, md: 3 }}>
                              <Icon as={FiSmartphone} color="gray.500" boxSize={{ base: 4, md: 5 }} />
                              <Text fontSize={{ base: 'sm', md: 'md' }}>Push Notifications</Text>
                            </HStack>
                            <Switch
                              colorScheme="brand"
                              size={{ base: 'sm', md: 'md' }}
                              isChecked={pushNotifications}
                              onChange={(e) => setPushNotifications(e.target.checked)}
                            />
                          </Stack>
                        </VStack>
                      </Box>
                    </VStack>
                  </CardBody>
                </Card>
              </VStack>
            </TabPanel>

            {/* Devices Tab */}
            <TabPanel px={0}>
              <Card>
                <CardBody>
                  <Heading size={{ base: 'xs', md: 'sm' }} mb={4}>
                    Connected Devices
                  </Heading>
                  <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.600" mb={4}>
                    Manage devices that are currently logged into your account
                  </Text>
                  <Box overflowX="auto">
                    <Table variant="simple" size={{ base: 'sm', md: 'md' }}>
                      <Thead>
                        <Tr>
                          <Th fontSize={{ base: 'xs', md: 'sm' }}>Device</Th>
                          <Th fontSize={{ base: 'xs', md: 'sm' }}>Location</Th>
                          <Th fontSize={{ base: 'xs', md: 'sm' }}>Last Active</Th>
                          <Th fontSize={{ base: 'xs', md: 'sm' }}>Actions</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {devices.map((device) => (
                          <Tr key={device.id}>
                            <Td>
                              <HStack spacing={{ base: 2, md: 3 }}>
                                <Icon as={FiMonitor} boxSize={{ base: 4, md: 5 }} />
                                <Box>
                                  <Text fontWeight="500" fontSize={{ base: 'xs', md: 'sm' }}>{device.device_name}</Text>
                                  {device.is_current && (
                                    <Badge colorScheme="green" fontSize="xs">
                                      Current Device
                                    </Badge>
                                  )}
                                </Box>
                              </HStack>
                            </Td>
                            <Td fontSize={{ base: 'xs', md: 'sm' }}>{device.location}</Td>
                            <Td fontSize={{ base: 'xs', md: 'sm' }} color="gray.600">
                              {formatRelativeTime(device.last_active)}
                            </Td>
                            <Td>
                              {!device.is_current && (
                                <Button
                                  size={{ base: 'xs', md: 'sm' }}
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => handleLogoutDevice(device.id)}
                                >
                                  Logout
                                </Button>
                              )}
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </Box>
                </CardBody>
              </Card>
            </TabPanel>

            {/* Account Tab */}
            <TabPanel px={0}>
              <VStack spacing={{ base: 4, md: 6 }} align="stretch">
                <Card>
                  <CardBody>
                    <Heading size={{ base: 'xs', md: 'sm' }} mb={4}>
                      Data & Privacy
                    </Heading>
                    <VStack align="stretch" spacing={3}>
                      <Button variant="outline" size={{ base: 'xs', md: 'sm' }}>
                        Download My Data
                      </Button>
                      <Button variant="outline" size={{ base: 'xs', md: 'sm' }}>
                        View Privacy Policy
                      </Button>
                      <Button variant="outline" size={{ base: 'xs', md: 'sm' }}>
                        View Terms of Service
                      </Button>
                    </VStack>
                  </CardBody>
                </Card>
              </VStack>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>
    </Container>
  );
};
