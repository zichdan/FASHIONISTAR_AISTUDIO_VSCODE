import { Box, useDisclosure } from '@chakra-ui/react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface MainLayoutProps {
  children: React.ReactNode;
}

export const MainLayout = ({ children }: MainLayoutProps) => {
  const { isOpen, onOpen, onClose } = useDisclosure();

  return (
    <Box minH="100vh" bg="gray.50">
      <Sidebar isOpen={isOpen} onClose={onClose} />
      <Header onMenuClick={onOpen} />
      <Box ml={{ base: 0, md: '260px' }} pt="70px">
        <Box p={{ base: 4, md: 8 }}>{children}</Box>
      </Box>
    </Box>
  );
};

export default MainLayout;
