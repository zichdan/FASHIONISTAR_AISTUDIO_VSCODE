import { useEffect, useRef, useState } from 'react';
import { Box, Button } from '@chakra-ui/react';

interface GoogleSignInButtonProps {
  onSuccess: (credentialResponse: any) => void;
  onError: () => void;
  text?: string;
  isLoading?: boolean;
}

const GoogleSignInButton = ({ onSuccess, onError, text = 'Sign in with Google', isLoading = false }: GoogleSignInButtonProps) => {
  const [isGoogleReady, setIsGoogleReady] = useState(false);
  const [isClicking, setIsClicking] = useState(false);
  const hiddenButtonRef = useRef<HTMLDivElement>(null);
  const initialized = useRef(false);

  const handleCredentialResponse = async (response: any) => {
    setIsClicking(false);
    onSuccess(response);
  };

  // Initialize Google Sign-In
  useEffect(() => {
    const initGoogle = async () => {
      // Wait for Google to be available
      let attempts = 0;
      while (typeof window.google === 'undefined' && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }

      if (typeof window.google !== 'undefined' && !initialized.current) {
        try {
          window.google.accounts.id.initialize({
            client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
            callback: handleCredentialResponse,
            auto_select: false,
            cancel_on_tap_outside: true,
          });

          setIsGoogleReady(true);
          initialized.current = true;
        } catch (error) {
          console.error('Failed to initialize Google Sign-In:', error);
          setIsGoogleReady(true); // Show button anyway as fallback
        }
      } else if (typeof window.google === 'undefined') {
        console.error('Google Sign-In script failed to load');
        setIsGoogleReady(true); // Show fallback button
      }
    };

    initGoogle();
  }, []);

  // Render hidden Google button
  useEffect(() => {
    if (isGoogleReady && typeof window.google !== 'undefined' && hiddenButtonRef.current && !hiddenButtonRef.current.hasChildNodes()) {
      try {
        window.google.accounts.id.renderButton(hiddenButtonRef.current, {
          theme: 'outline',
          size: 'large',
          text: 'signin_with',
          shape: 'rectangular',
          width: '250px',
        });
      } catch (error) {
        console.error('Failed to render hidden Google button:', error);
      }
    }
  }, [isGoogleReady]);

  const handleGoogleSignIn = async () => {
    if (typeof window.google === 'undefined') {
      onError();
      return;
    }

    setIsClicking(true);

    // Try to click the hidden Google button first
    try {
      const hiddenButton = hiddenButtonRef.current?.querySelector('div[role="button"]') as HTMLElement;
      if (hiddenButton) {
        hiddenButton.click();
        return;
      }
    } catch (error) {
      console.log('Hidden button click failed, trying prompt:', error);
    }

    // Fallback to prompt
    try {
      window.google.accounts.id.prompt((notification: any) => {
        setIsClicking(false);
        if (notification.isNotDisplayed()) {
          console.log('Google Sign-In prompt was not displayed');
          onError();
        } else if (notification.isSkippedMoment()) {
          console.log('Google Sign-In prompt was skipped');
        }
      });
    } catch (error) {
      setIsClicking(false);
      console.error('Error triggering Google Sign-In:', error);
      onError();
    }
  };

  if (!isGoogleReady) {
    return (
      <Button
        width="100%"
        height="44px"
        border="1px solid #dadce0"
        borderRadius="md"
        background="white"
        color="#666"
        fontSize="14px"
        fontWeight="500"
        isLoading
        loadingText="Loading Google Sign-In..."
        variant="outline"
        _hover={{ background: "white" }}
        _active={{ background: "white" }}
        cursor="not-allowed"
      />
    );
  }

  return (
    <Box position="relative" width="100%">
      {/* Hidden Google button */}
      <Box
        ref={hiddenButtonRef}
        position="absolute"
        left="-9999px"
        visibility="hidden"
        pointerEvents="none"
      />

      {/* Custom visible button */}
      <Button
        width="100%"
        height="44px"
        border="1px solid #dadce0"
        borderRadius="md"
        background="white"
        color="#3c4043"
        fontSize="14px"
        fontWeight="500"
        leftIcon={
          <svg width="18" height="18" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
        }
        onClick={handleGoogleSignIn}
        isLoading={isClicking || isLoading}
        variant="outline"
        _hover={{
          boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
          borderColor: '#dadce0',
          background: 'white'
        }}
        _active={{
          background: '#f8f9fa'
        }}
      >
        {text}
      </Button>
    </Box>
  );
};

export default GoogleSignInButton;
