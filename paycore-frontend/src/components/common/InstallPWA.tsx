import { useState, useEffect } from 'react';
import {
  Button,
  useToast,
  IconButton,
  Tooltip,
} from '@chakra-ui/react';
import { FiDownload } from 'react-icons/fi';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

interface InstallPWAProps {
  variant?: 'button' | 'icon';
  size?: 'sm' | 'md' | 'lg';
}

export const InstallPWA = ({ variant = 'icon', size = 'md' }: InstallPWAProps) => {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstallable, setIsInstallable] = useState(false);
  const toast = useToast();

  useEffect(() => {
    const handler = (e: Event) => {
      // Prevent the default mini-infobar from appearing
      e.preventDefault();
      // Save the event for later use
      setDeferredPrompt(e as BeforeInstallPromptEvent);
      setIsInstallable(true);
      console.log('[PWA] Install prompt is available');
    };

    window.addEventListener('beforeinstallprompt', handler);

    // Check if app is already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      console.log('[PWA] App is already installed');
      setIsInstallable(false);
    }

    return () => {
      window.removeEventListener('beforeinstallprompt', handler);
    };
  }, []);

  const handleInstallClick = async () => {
    if (!deferredPrompt) {
      toast({
        title: 'Installation Not Available',
        description: 'The app is either already installed or not installable on this device.',
        status: 'info',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    // Show the install prompt
    await deferredPrompt.prompt();

    // Wait for the user to respond to the prompt
    const { outcome } = await deferredPrompt.userChoice;

    if (outcome === 'accepted') {
      console.log('[PWA] User accepted the install prompt');
      toast({
        title: 'App Installed!',
        description: 'PayCore has been installed successfully.',
        status: 'success',
        duration: 3000,
        isClosable: true,
      });
    } else {
      console.log('[PWA] User dismissed the install prompt');
    }

    // Clear the saved prompt since it can't be used again
    setDeferredPrompt(null);
    setIsInstallable(false);
  };

  // Don't show the button if not installable
  if (!isInstallable) {
    return null;
  }

  if (variant === 'icon') {
    return (
      <Tooltip label="Install App" placement="bottom">
        <IconButton
          aria-label="Install app"
          icon={<FiDownload />}
          onClick={handleInstallClick}
          size={size}
          variant="ghost"
          colorScheme="brand"
        />
      </Tooltip>
    );
  }

  return (
    <Button
      leftIcon={<FiDownload />}
      onClick={handleInstallClick}
      size={size}
      colorScheme="brand"
      variant="outline"
    >
      Install App
    </Button>
  );
};
