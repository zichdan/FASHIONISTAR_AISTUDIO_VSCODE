import { Box, VStack, Text, Icon, Flex, Avatar, Divider, Drawer, DrawerContent, DrawerOverlay, DrawerCloseButton, useBreakpointValue } from '@chakra-ui/react';
import { Link, useLocation } from 'react-router-dom';
import {
  FiHome,
  FiCreditCard,
  FiDollarSign,
  FiShoppingCart,
  FiFileText,
  FiTrendingUp,
  FiPieChart,
  FiHelpCircle,
  FiMessageCircle,
  FiSettings,
} from 'react-icons/fi';
import { useGetProfileQuery } from '@/features/profile/services/profileApi';

interface NavItem {
  label: string;
  icon: React.ElementType;
  path: string;
}

const navItems: NavItem[] = [
  { label: 'Dashboard', icon: FiHome, path: '/dashboard' },
  { label: 'Wallets', icon: FiCreditCard, path: '/wallets' },
  { label: 'Cards', icon: FiCreditCard, path: '/cards' },
  { label: 'Transactions', icon: FiDollarSign, path: '/transactions' },
  { label: 'Bills', icon: FiShoppingCart, path: '/bills' },
  { label: 'Payments', icon: FiFileText, path: '/payments' },
  { label: 'Loans', icon: FiTrendingUp, path: '/loans' },
  { label: 'Investments', icon: FiPieChart, path: '/investments' },
  { label: 'Support', icon: FiHelpCircle, path: '/support' },
  { label: 'My Tickets', icon: FiMessageCircle, path: '/tickets' },
  { label: 'Settings', icon: FiSettings, path: '/settings' },
];

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

const SidebarContent = ({ onClose }: { onClose?: () => void }) => {
  const location = useLocation();
  const { data: profileData } = useGetProfileQuery();
  const profile = profileData?.data;

  const isActive = (path: string) => {
    return location.pathname.startsWith(path);
  };

  const handleNavClick = () => {
    if (onClose) {
      onClose();
    }
  };

  return (
    <VStack spacing={6} align="stretch" h="full">
      {/* Logo */}
      <Box px={6}>
        <Text fontSize="2xl" fontWeight="bold" color="brand.500">
          PayCore
        </Text>
      </Box>

      <Divider />

      {/* Navigation */}
      <VStack spacing={1} px={3} flex={1}>
        {navItems.map((item) => {
          const active = isActive(item.path);
          return (
            <Link key={item.path} to={item.path} style={{ width: '100%' }} onClick={handleNavClick}>
              <Flex
                align="center"
                px={4}
                py={3}
                borderRadius="lg"
                cursor="pointer"
                bg={active ? 'brand.50' : 'transparent'}
                color={active ? 'brand.600' : 'gray.600'}
                fontWeight={active ? '600' : '400'}
                _hover={{
                  bg: active ? 'brand.50' : 'gray.50',
                  color: active ? 'brand.600' : 'gray.900',
                }}
                transition="all 0.2s"
              >
                <Icon as={item.icon} boxSize={5} mr={3} />
                <Text fontSize="sm">{item.label}</Text>
              </Flex>
            </Link>
          );
        })}
      </VStack>

      <Divider />

      {/* User Profile */}
      <Box px={6}>
        <Link to="/profile" onClick={handleNavClick}>
          <Flex align="center" cursor="pointer" _hover={{ opacity: 0.8 }}>
            <Avatar
              size="sm"
              name={`${profile?.first_name} ${profile?.last_name}`}
              src={profile?.avatar_url || undefined}
              bg="brand.500"
              color="white"
              fontWeight="bold"
              mr={3}
            />
            <Box>
              <Text fontSize="sm" fontWeight="600">
                {profile?.first_name} {profile?.last_name}
              </Text>
              <Text fontSize="xs" color="gray.500">
                {profile?.email}
              </Text>
            </Box>
          </Flex>
        </Link>
      </Box>
    </VStack>
  );
};

export const Sidebar = ({ isOpen, onClose }: SidebarProps) => {
  const isMobile = useBreakpointValue({ base: true, md: false });

  if (isMobile) {
    return (
      <Drawer isOpen={isOpen || false} placement="left" onClose={onClose || (() => {})}>
        <DrawerOverlay />
        <DrawerContent>
          <DrawerCloseButton />
          <Box py={6} overflowY="auto" h="100vh">
            <SidebarContent onClose={onClose} />
          </Box>
        </DrawerContent>
      </Drawer>
    );
  }

  return (
    <Box
      as="nav"
      pos="fixed"
      left="0"
      top="0"
      h="100vh"
      w="260px"
      bg="white"
      borderRight="1px"
      borderColor="gray.200"
      py={6}
      overflowY="auto"
      display={{ base: 'none', md: 'block' }}
    >
      <SidebarContent />
    </Box>
  );
};
