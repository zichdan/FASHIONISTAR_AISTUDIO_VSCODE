import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Heading,
  HStack,
  Link,
  PinInput,
  PinInputField,
  Stack,
  Text,
  useToast,
  VStack,
  Alert,
  AlertIcon,
} from '@chakra-ui/react';
import { Link as RouterLink, useNavigate, useLocation } from 'react-router-dom';
import { useVerifyOTPMutation } from '@/features/auth/services/authApi';
import { useDispatch } from 'react-redux';
import { setCredentials } from '@/store/slices/authSlice';
import { fcmService } from '@/services/fcm.service';

export const VerifyOTPPage = () => {
  const [otp, setOtp] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const dispatch = useDispatch();

  const email = location.state?.email;

  const [verifyOTP, { isLoading }] = useVerifyOTPMutation();

  // Redirect if no email provided
  useEffect(() => {
    if (!email) {
      toast({
        title: 'Error',
        description: 'No email provided. Please login again.',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      navigate('/login');
    }
  }, [email, navigate, toast]);

  const handleOtpChange = (value: string) => {
    setOtp(value);

    // Auto-submit when OTP is complete
    if (value.length === 6) {
      handleVerifyOTP(value);
    }
  };

  const handleVerifyOTP = async (otpValue?: string) => {
    const otpToVerify = otpValue || otp;

    if (otpToVerify.length !== 6) {
      toast({
        title: 'Invalid OTP',
        description: 'Please enter a 6-digit OTP',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    try {
      // Get FCM device token for push notifications
      const deviceToken = await fcmService.getDeviceToken();

      const response = await verifyOTP({
        email: email,
        otp: parseInt(otpToVerify),
        device_type: 'web',
        device_token: deviceToken || undefined,
      }).unwrap();

      // Store tokens and user data in Redux
      localStorage.setItem('access_token', response.data.access);
      if (response.data.refresh) {
        localStorage.setItem('refresh_token', response.data.refresh);
      }

      dispatch(
        setCredentials({
          user: response.data.user,
          accessToken: response.data.access,
          refreshToken: response.data.refresh,
        })
      );

      toast({
        title: 'Login successful',
        description: `Welcome back, ${response.data.user.first_name}!`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      });

      // Navigate to dashboard
      navigate('/dashboard');
    } catch (error: any) {
      toast({
        title: 'Verification failed',
        description: error?.data?.message || error?.data?.detail || 'Invalid OTP. Please try again.',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
      setOtp('');
    }
  };

  if (!email) {
    return null;
  }

  return (
    <VStack spacing={6} align="stretch">
      {/* Header */}
      <VStack spacing={2} textAlign="center">
        <Heading
          as="h1"
          size="xl"
          bgGradient="linear(to-r, brand.500, brand.600)"
          bgClip="text"
        >
          Verify Your Identity
        </Heading>
        <Text fontSize="sm" color="gray.600" textAlign="center">
          We've sent a 6-digit verification code to{' '}
          <Text as="span" fontWeight="semibold" color="brand.600">
            {email}
          </Text>
        </Text>
      </VStack>

      {/* OTP Form */}
      <Stack spacing={6}>
        {/* OTP Input */}
        <VStack spacing={4}>
          <Text fontSize="sm" color="gray.600" fontWeight="semibold">
            Enter verification code
          </Text>
          <HStack spacing={2} justify="center">
            <PinInput
              otp
              size="lg"
              value={otp}
              onChange={handleOtpChange}
              placeholder=""
              focusBorderColor="brand.500"
              errorBorderColor="red.500"
            >
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
              <PinInputField w="45px" h="56px" fontSize="xl" fontWeight="bold" />
            </PinInput>
          </HStack>
        </VStack>

        {/* Verify Button */}
        <Button
          colorScheme="brand"
          size="lg"
          isLoading={isLoading}
          loadingText="Verifying..."
          onClick={() => handleVerifyOTP()}
          w="full"
          isDisabled={otp.length !== 6}
        >
          Verify OTP
        </Button>

        {/* Security Notice */}
        <Alert status="info" borderRadius="md" variant="left-accent">
          <AlertIcon />
          <Box>
            <Text fontSize="xs" fontWeight="semibold">
              Security Notice
            </Text>
            <Text fontSize="xs">
              Never share your verification code with anyone. PayCore will never ask for your OTP via phone or email.
            </Text>
          </Box>
        </Alert>

        {/* Back to Login Link */}
        <HStack justify="center" spacing={1} pt={2}>
          <Text color="gray.600" fontSize="sm">
            Wrong email?
          </Text>
          <Link
            as={RouterLink}
            to="/login"
            color="brand.500"
            fontWeight="semibold"
            fontSize="sm"
            _hover={{ color: 'brand.600', textDecoration: 'underline' }}
          >
            Go back to login
          </Link>
        </HStack>
      </Stack>
    </VStack>
  );
};

export default VerifyOTPPage;
