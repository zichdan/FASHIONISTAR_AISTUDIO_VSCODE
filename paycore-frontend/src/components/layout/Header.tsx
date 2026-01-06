import {
  Box,
  Flex,
  IconButton,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  MenuDivider,
  Badge,
  Text,
  Avatar,
  HStack,
  useDisclosure,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  VStack,
  Button,
  Icon,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Divider,
  Checkbox,
  useToast,
} from '@chakra-ui/react';
import { FiBell, FiLogOut, FiUser, FiSettings, FiCheck, FiTrash2, FiCheckCircle, FiMenu } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/hooks';
import { logout } from '@/store/slices/authSlice';
import { useLogoutMutation } from '@/features/auth/services/authApi';
import {
  useListNotificationsQuery,
  useMarkAsReadMutation,
  useDeleteNotificationsMutation,
} from '@/features/notifications/services/notificationsApi';
import { useGetProfileQuery } from '@/features/profile/services/profileApi';
import { formatRelativeTime } from '@/utils/formatters';
import { useState, useEffect } from 'react';
import { useWebSocketContext } from '@/contexts/WebSocketContext';
import { InstallPWA } from '@/components/common/InstallPWA';

interface HeaderProps {
  onMenuClick?: () => void;
}

export const Header = ({ onMenuClick }: HeaderProps) => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const toast = useToast();
  const [logoutMutation] = useLogoutMutation();
  const { isOpen: isNotificationsOpen, onOpen: onNotificationsOpen, onClose: onNotificationsClose } = useDisclosure();
  const [selectedNotifications, setSelectedNotifications] = useState<string[]>([]);

  // Fetch profile data
  const { data: profileData } = useGetProfileQuery();
  const profile = profileData?.data;

  // Fetch notifications - limited for header badge, unlimited for modal
  const { data: notificationsData, refetch: refetchNotifications } = useListNotificationsQuery({ limit: 5 });
  const { data: allNotificationsData, refetch: refetchAllNotifications, isLoading: loadingAllNotifications } = useListNotificationsQuery(
    { limit: 100 }
  );

  // WebSocket integration for real-time notifications
  const { latestNotification, unreadCount: wsUnreadCount, markAsRead: wsMarkAsRead } = useWebSocketContext();

  // Refetch notifications when WebSocket receives a new notification
  useEffect(() => {
    if (latestNotification) {
      console.log('New WebSocket notification received, refetching notifications...');
      refetchNotifications();
      refetchAllNotifications();

      // Toast is already shown by WebSocketContext, no need to duplicate here
    }
  }, [latestNotification]);

  // Mutations
  const [markAsRead] = useMarkAsReadMutation();
  const [deleteNotifications] = useDeleteNotificationsMutation();

  // Backend returns notifications in data.notifications
  const unreadCount = (notificationsData?.data as any)?.unread_count || 0;
  const allNotifications = (allNotificationsData?.data as any)?.notifications || [];
  const unreadNotifications = allNotifications.filter((n: any) => !n.is_read);
  const readNotifications = allNotifications.filter((n: any) => n.is_read);

  const handleLogout = async () => {
    try {
      await logoutMutation().unwrap();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      dispatch(logout());
      navigate('/login');
    }
  };

  const handleMarkAsRead = async (notificationIds: string[]) => {
    try {
      await markAsRead({ notification_ids: notificationIds }).unwrap();

      // Send WebSocket update for real-time sync
      wsMarkAsRead(notificationIds);

      refetchAllNotifications();
      refetchNotifications();
      toast({
        title: 'Marked as read',
        status: 'success',
        duration: 2000,
      });
      setSelectedNotifications([]);
    } catch (error: any) {
      toast({
        title: 'Failed to mark as read',
        description: error?.data?.message || 'Please try again',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleMarkAllAsRead = async () => {
    try {
      await markAsRead({ mark_all: true }).unwrap();
      refetchAllNotifications();
      toast({
        title: 'All notifications marked as read',
        status: 'success',
        duration: 2000,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to mark as read',
        description: error?.data?.message || 'Please try again',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleDeleteNotifications = async (notificationIds: string[]) => {
    try {
      await deleteNotifications(notificationIds).unwrap();
      refetchAllNotifications();
      toast({
        title: 'Notifications deleted',
        status: 'success',
        duration: 2000,
      });
      setSelectedNotifications([]);
    } catch (error: any) {
      toast({
        title: 'Failed to delete notifications',
        description: error?.data?.message || 'Please try again',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const toggleNotificationSelection = (id: string) => {
    setSelectedNotifications((prev) =>
      prev.includes(id) ? prev.filter((nId) => nId !== id) : [...prev, id]
    );
  };

  const getNotificationTypeColor = (type: string) => {
    switch (type) {
      case 'transaction':
        return 'blue';
      case 'security':
        return 'red';
      case 'kyc':
        return 'purple';
      case 'loan':
        return 'orange';
      case 'investment':
        return 'green';
      case 'card':
        return 'teal';
      case 'system':
        return 'gray';
      case 'marketing':
        return 'pink';
      default:
        return 'gray';
    }
  };

  return (
    <Box
      as="header"
      pos="fixed"
      top="0"
      left={{ base: 0, md: '260px' }}
      right="0"
      h="70px"
      bg="white"
      borderBottom="1px"
      borderColor="gray.200"
      px={{ base: 4, md: 8 }}
      zIndex={10}
    >
      <Flex h="full" align="center" justify="space-between">
        <HStack spacing={4}>
          {/* Hamburger Menu for Mobile */}
          <IconButton
            icon={<FiMenu size={24} />}
            variant="ghost"
            aria-label="Open menu"
            onClick={onMenuClick}
            display={{ base: 'flex', md: 'none' }}
          />

          <Box>
            <Text fontSize={{ base: 'md', md: 'lg' }} fontWeight="600">
              Welcome back, {profile?.first_name}!
            </Text>
            <Text fontSize={{ base: 'xs', md: 'sm' }} color="gray.500" display={{ base: 'none', sm: 'block' }}>
              {new Date().toLocaleDateString('en-US', {
                weekday: 'long',
                year: 'numeric',
                month: 'long',
                day: 'numeric',
              })}
            </Text>
          </Box>
        </HStack>

        <HStack spacing={{ base: 2, md: 4 }}>
          {/* Install PWA Button */}
          <InstallPWA variant="icon" size="md" />

          {/* Notifications */}
          <Box position="relative">
            <IconButton
              icon={<FiBell size={20} />}
              variant="ghost"
              aria-label="Notifications"
              onClick={onNotificationsOpen}
              size={{ base: 'sm', md: 'md' }}
            />
            {unreadCount > 0 && (
              <Badge
                position="absolute"
                top="-2px"
                right="-2px"
                colorScheme="red"
                borderRadius="full"
                fontSize="xs"
                minW="18px"
                h="18px"
                display="flex"
                alignItems="center"
                justifyContent="center"
              >
                {unreadCount}
              </Badge>
            )}
          </Box>

          {/* User Menu */}
          <Menu>
            <MenuButton>
              <Avatar
                size="sm"
                name={`${profile?.first_name} ${profile?.last_name}`}
                src={profile?.avatar_url || undefined}
                bg="brand.500"
                color="white"
                fontWeight="bold"
                cursor="pointer"
              />
            </MenuButton>
            <MenuList>
              <MenuItem icon={<FiUser />} onClick={() => navigate('/profile')}>
                Profile
              </MenuItem>
              <MenuItem icon={<FiSettings />} onClick={() => navigate('/settings')}>
                Settings
              </MenuItem>
              <MenuDivider />
              <MenuItem icon={<FiLogOut />} onClick={handleLogout} color="red.500">
                Logout
              </MenuItem>
            </MenuList>
          </Menu>
        </HStack>
      </Flex>

      {/* Notifications Modal */}
      <Modal isOpen={isNotificationsOpen} onClose={onNotificationsClose} size={{ base: 'full', md: '4xl' }}>
        <ModalOverlay />
        <ModalContent maxH="80vh">
          <ModalHeader>
            <HStack justify="space-between">
              <HStack>
                <Icon as={FiBell} color="brand.500" boxSize={6} />
                <Text>All Notifications</Text>
                {unreadCount > 0 && (
                  <Badge colorScheme="red" borderRadius="full">
                    {unreadCount} unread
                  </Badge>
                )}
              </HStack>
              <HStack>
                {selectedNotifications.length > 0 && (
                  <>
                    <Button
                      size="sm"
                      leftIcon={<FiCheck />}
                      onClick={() => handleMarkAsRead(selectedNotifications)}
                    >
                      Mark as Read
                    </Button>
                    <Button
                      size="sm"
                      colorScheme="red"
                      variant="ghost"
                      leftIcon={<FiTrash2 />}
                      onClick={() => handleDeleteNotifications(selectedNotifications)}
                    >
                      Delete
                    </Button>
                  </>
                )}
                {unreadNotifications.length > 0 && (
                  <Button
                    size="sm"
                    variant="ghost"
                    leftIcon={<FiCheckCircle />}
                    onClick={handleMarkAllAsRead}
                  >
                    Mark All as Read
                  </Button>
                )}
              </HStack>
            </HStack>
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
            <Tabs>
              <TabList>
                <Tab>All ({allNotifications.length})</Tab>
                <Tab>Unread ({unreadNotifications.length})</Tab>
                <Tab>Read ({readNotifications.length})</Tab>
              </TabList>

              <TabPanels>
                {/* All Notifications */}
                <TabPanel px={0}>
                  <VStack align="stretch" spacing={2} maxH="500px" overflowY="auto">
                    {allNotifications.length > 0 ? (
                      allNotifications.map((notification: any) => (
                        <Box
                          key={notification.id}
                          p={4}
                          borderWidth="1px"
                          borderRadius="md"
                          bg={notification.is_read ? 'white' : 'blue.50'}
                          _hover={{ bg: notification.is_read ? 'gray.50' : 'blue.100' }}
                          cursor="pointer"
                        >
                          <HStack align="start" spacing={3}>
                            <Checkbox
                              isChecked={selectedNotifications.includes(notification.id)}
                              onChange={() => toggleNotificationSelection(notification.id)}
                            />
                            <Box flex="1">
                              <HStack justify="space-between" mb={1}>
                                <HStack>
                                  <Text fontWeight="600" fontSize="sm">
                                    {notification.title}
                                  </Text>
                                  <Badge
                                    colorScheme={getNotificationTypeColor(notification.notification_type)}
                                    fontSize="xs"
                                    textTransform="capitalize"
                                  >
                                    {notification.notification_type}
                                  </Badge>
                                  {!notification.is_read && (
                                    <Badge colorScheme="blue" fontSize="xs">
                                      NEW
                                    </Badge>
                                  )}
                                </HStack>
                                <Text fontSize="xs" color="gray.500">
                                  {formatRelativeTime(notification.created_at)}
                                </Text>
                              </HStack>
                              <Text fontSize="sm" color="gray.600">
                                {notification.message}
                              </Text>
                              {notification.action_url && (
                                <Button
                                  size="xs"
                                  colorScheme="brand"
                                  variant="ghost"
                                  mt={2}
                                  onClick={() => {
                                    navigate(notification.action_url);
                                    onNotificationsClose();
                                  }}
                                >
                                  View Details
                                </Button>
                              )}
                            </Box>
                          </HStack>
                        </Box>
                      ))
                    ) : (
                      <Box textAlign="center" py={8}>
                        <Icon as={FiBell} boxSize={12} color="gray.300" />
                        <Text color="gray.500" mt={2}>
                          No notifications
                        </Text>
                      </Box>
                    )}
                  </VStack>
                </TabPanel>

                {/* Unread Notifications */}
                <TabPanel px={0}>
                  <VStack align="stretch" spacing={2} maxH="500px" overflowY="auto">
                    {unreadNotifications.length > 0 ? (
                      unreadNotifications.map((notification: any) => (
                        <Box
                          key={notification.id}
                          p={4}
                          borderWidth="1px"
                          borderRadius="md"
                          bg="blue.50"
                          _hover={{ bg: 'blue.100' }}
                          cursor="pointer"
                        >
                          <HStack align="start" spacing={3}>
                            <Checkbox
                              isChecked={selectedNotifications.includes(notification.id)}
                              onChange={() => toggleNotificationSelection(notification.id)}
                            />
                            <Box flex="1">
                              <HStack justify="space-between" mb={1}>
                                <HStack>
                                  <Text fontWeight="600" fontSize="sm">
                                    {notification.title}
                                  </Text>
                                  <Badge
                                    colorScheme={getNotificationTypeColor(notification.notification_type)}
                                    fontSize="xs"
                                    textTransform="capitalize"
                                  >
                                    {notification.notification_type}
                                  </Badge>
                                  <Badge colorScheme="blue" fontSize="xs">
                                    NEW
                                  </Badge>
                                </HStack>
                                <Text fontSize="xs" color="gray.500">
                                  {formatRelativeTime(notification.created_at)}
                                </Text>
                              </HStack>
                              <Text fontSize="sm" color="gray.600">
                                {notification.message}
                              </Text>
                              {notification.action_url && (
                                <Button
                                  size="xs"
                                  colorScheme="brand"
                                  variant="ghost"
                                  mt={2}
                                  onClick={() => {
                                    navigate(notification.action_url);
                                    onNotificationsClose();
                                  }}
                                >
                                  View Details
                                </Button>
                              )}
                            </Box>
                          </HStack>
                        </Box>
                      ))
                    ) : (
                      <Box textAlign="center" py={8}>
                        <Icon as={FiBell} boxSize={12} color="gray.300" />
                        <Text color="gray.500" mt={2}>
                          No unread notifications
                        </Text>
                      </Box>
                    )}
                  </VStack>
                </TabPanel>

                {/* Read Notifications */}
                <TabPanel px={0}>
                  <VStack align="stretch" spacing={2} maxH="500px" overflowY="auto">
                    {readNotifications.length > 0 ? (
                      readNotifications.map((notification: any) => (
                        <Box
                          key={notification.id}
                          p={4}
                          borderWidth="1px"
                          borderRadius="md"
                          bg="white"
                          _hover={{ bg: 'gray.50' }}
                          cursor="pointer"
                        >
                          <HStack align="start" spacing={3}>
                            <Checkbox
                              isChecked={selectedNotifications.includes(notification.id)}
                              onChange={() => toggleNotificationSelection(notification.id)}
                            />
                            <Box flex="1">
                              <HStack justify="space-between" mb={1}>
                                <HStack>
                                  <Text fontWeight="600" fontSize="sm" color="gray.600">
                                    {notification.title}
                                  </Text>
                                  <Badge
                                    colorScheme={getNotificationTypeColor(notification.notification_type)}
                                    fontSize="xs"
                                    textTransform="capitalize"
                                  >
                                    {notification.notification_type}
                                  </Badge>
                                </HStack>
                                <Text fontSize="xs" color="gray.500">
                                  {formatRelativeTime(notification.created_at)}
                                </Text>
                              </HStack>
                              <Text fontSize="sm" color="gray.500">
                                {notification.message}
                              </Text>
                              {notification.action_url && (
                                <Button
                                  size="xs"
                                  colorScheme="brand"
                                  variant="ghost"
                                  mt={2}
                                  onClick={() => {
                                    navigate(notification.action_url);
                                    onNotificationsClose();
                                  }}
                                >
                                  View Details
                                </Button>
                              )}
                            </Box>
                          </HStack>
                        </Box>
                      ))
                    ) : (
                      <Box textAlign="center" py={8}>
                        <Icon as={FiBell} boxSize={12} color="gray.300" />
                        <Text color="gray.500" mt={2}>
                          No read notifications
                        </Text>
                      </Box>
                    )}
                  </VStack>
                </TabPanel>
              </TabPanels>
            </Tabs>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Box>
  );
};
