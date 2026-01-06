import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Container,
  FormControl,
  FormErrorMessage,
  FormLabel,
  Heading,
  HStack,
  Input,
  InputGroup,
  InputRightElement,
  Link,
  PinInput,
  PinInputField,
  Progress,
  Stack,
  Text,
  useToast,
  VStack,
  IconButton,
  List,
  ListItem,
  ListIcon,
} from '@chakra-ui/react';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import { ViewIcon, ViewOffIcon, CheckCircleIcon, WarningIcon, ArrowBackIcon } from '@chakra-ui/icons';
import { useForgotPasswordMutation, useResetPasswordMutation } from '@/features/auth/services/authApi';
import { handleApiError } from '@/utils/formErrorHandler';

// Password strength checker
const checkPasswordStrength = (password: string): number => {
  let strength = 0;
  if (password.length >= 8) strength += 20;
  if (password.length >= 12) strength += 10;
  if (/[a-z]/.test(password)) strength += 20;
  if (/[A-Z]/.test(password)) strength += 20;
  if (/[0-9]/.test(password)) strength += 15;
  if (/[^a-zA-Z0-9]/.test(password)) strength += 15;
  return strength;
};

const getPasswordStrengthColor = (strength: number): string => {
  if (strength < 40) return 'red';
  if (strength < 60) return 'orange';
  if (strength < 80) return 'yellow';
  return 'green';
};

const getPasswordStrengthText = (strength: number): string => {
  if (strength < 40) return 'Weak';
  if (strength < 60) return 'Fair';
  if (strength < 80) return 'Good';
  return 'Strong';
};

// Step 1: Email validation schema
const emailSchema = yup.object().shape({
  email: yup
    .string()
    .email('Invalid email address')
    .required('Email is required'),
});

// Step 2: Reset password validation schema
const resetPasswordSchema = yup.object().shape({
  new_password: yup
    .string()
    .min(8, 'Password must be at least 8 characters')
    .matches(/[a-z]/, 'Password must contain at least one lowercase letter')
    .matches(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .matches(/[0-9]/, 'Password must contain at least one number')
    .matches(/[^a-zA-Z0-9]/, 'Password must contain at least one special character')
    .required('Password is required'),
  confirmPassword: yup
    .string()
    .oneOf([yup.ref('new_password')], 'Passwords must match')
    .required('Please confirm your password'),
});

interface EmailFormData {
  email: string;
}

interface ResetPasswordFormData {
  new_password: string;
  confirmPassword: string;
}

const ForgotPasswordPage = () => {
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [countdown, setCountdown] = useState(60);
  const [canResend, setCanResend] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  const [forgotPassword, { isLoading: isSendingOTP }] = useForgotPasswordMutation();
  const [resetPassword, { isLoading: isResetting }] = useResetPasswordMutation();

  // Step 1 form
  const {
    register: registerEmail,
    handleSubmit: handleSubmitEmail,
    setError: setEmailError,
    formState: { errors: emailErrors },
  } = useForm<EmailFormData>({
    resolver: yupResolver(emailSchema),
  });

  // Step 2 form
  const {
    register: registerReset,
    handleSubmit: handleSubmitReset,
    setError: setResetError,
    formState: { errors: resetErrors },
    watch,
  } = useForm<ResetPasswordFormData>({
    resolver: yupResolver(resetPasswordSchema),
  });

  const newPassword = watch('new_password');

  // Countdown timer for resend OTP
  useEffect(() => {
    if (step === 2) {
      if (countdown > 0) {
        const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
        return () => clearTimeout(timer);
      } else {
        setCanResend(true);
      }
    }
  }, [countdown, step]);

  // Update password strength
  useEffect(() => {
    if (newPassword) {
      setPasswordStrength(checkPasswordStrength(newPassword));
    } else {
      setPasswordStrength(0);
    }
  }, [newPassword]);

  // Step 1: Send OTP to email
  const onSubmitEmail = async (data: EmailFormData) => {
    try {
      const response = await forgotPassword({ email: data.email }).unwrap();

      toast({
        title: 'OTP sent',
        description: response.message || 'A verification code has been sent to your email',
        status: 'success',
        duration: 5000,
        isClosable: true,
        position: 'top-right',
      });

      setEmail(data.email);
      setStep(2);
      setCountdown(60);
      setCanResend(false);
    } catch (error: any) {
      handleApiError(error, setEmailError, toast);
    }
  };

  // Step 2: Verify OTP and reset password
  const onSubmitReset = async (data: ResetPasswordFormData) => {
    if (otp.length !== 6) {
      toast({
        title: 'Invalid OTP',
        description: 'Please enter a 6-digit verification code',
        status: 'warning',
        duration: 3000,
        isClosable: true,
        position: 'top-right',
      });
      return;
    }

    try {
      const response = await resetPassword({
        email: email,
        otp: parseInt(otp),
        new_password: data.new_password,
      }).unwrap();

      toast({
        title: 'Password reset successful',
        description: response.message || 'Your password has been reset. You can now login with your new password.',
        status: 'success',
        duration: 5000,
        isClosable: true,
        position: 'top-right',
      });

      // Navigate to login page
      setTimeout(() => {
        navigate('/auth/login');
      }, 2000);
    } catch (error: any) {
      handleApiError(error, setResetError, toast);
    }
  };

  const handleResendOTP = async () => {
    if (!canResend) return;

    try {
      const response = await forgotPassword({ email: email }).unwrap();

      toast({
        title: 'OTP resent',
        description: response.message || 'A new verification code has been sent to your email',
        status: 'success',
        duration: 3000,
        isClosable: true,
        position: 'top-right',
      });

      setCountdown(60);
      setCanResend(false);
      setOtp('');
    } catch (error: any) {
      toast({
        title: 'Failed to resend OTP',
        description: error?.data?.message || 'Please try again later',
        status: 'error',
        duration: 3000,
        isClosable: true,
        position: 'top-right',
      });
    }
  };

  const handleBackToStep1 = () => {
    setStep(1);
    setOtp('');
    setCountdown(60);
    setCanResend(false);
  };

  const passwordRequirements = [
    { text: 'At least 8 characters', met: newPassword?.length >= 8 },
    { text: 'One uppercase letter', met: /[A-Z]/.test(newPassword || '') },
    { text: 'One lowercase letter', met: /[a-z]/.test(newPassword || '') },
    { text: 'One number', met: /[0-9]/.test(newPassword || '') },
    { text: 'One special character', met: /[^a-zA-Z0-9]/.test(newPassword || '') },
  ];

  return (
    <Box minH="100vh" bg="gray.50" py={12} px={4}>
      <Container maxW="md">
        <VStack spacing={8} align="stretch">
          {/* Logo and Header */}
          <VStack spacing={2} textAlign="center">
            <Heading
              as="h1"
              size="2xl"
              bgGradient="linear(to-r, brand.500, brand.600)"
              bgClip="text"
              fontWeight="extrabold"
            >
              PayCore
            </Heading>
            <Heading as="h2" size="lg" color="gray.800" mt={4}>
              Reset Password
            </Heading>
            <Text fontSize="md" color="gray.600">
              {step === 1
                ? 'Enter your email to receive a verification code'
                : 'Enter the code and your new password'}
            </Text>
          </VStack>

          {/* Progress Indicator */}
          <Box>
            <HStack justify="space-between" mb={2}>
              <Text fontSize="xs" fontWeight="semibold" color={step === 1 ? 'brand.500' : 'green.500'}>
                Step 1: Verify Email
              </Text>
              <Text fontSize="xs" fontWeight="semibold" color={step === 2 ? 'brand.500' : 'gray.400'}>
                Step 2: Reset Password
              </Text>
            </HStack>
            <Progress value={step === 1 ? 50 : 100} size="sm" colorScheme="brand" borderRadius="full" />
          </Box>

          {/* Form */}
          <Box
            bg="white"
            py={8}
            px={10}
            shadow="lg"
            borderRadius="xl"
            borderWidth="1px"
            borderColor="gray.200"
          >
            {step === 1 ? (
              // Step 1: Email Form
              <form onSubmit={handleSubmitEmail(onSubmitEmail)}>
                <Stack spacing={6}>
                  <FormControl isInvalid={!!emailErrors.email}>
                    <FormLabel htmlFor="email" fontWeight="semibold">
                      Email address
                    </FormLabel>
                    <Input
                      id="email"
                      type="email"
                      placeholder="Enter your email"
                      size="lg"
                      {...registerEmail('email')}
                    />
                    <FormErrorMessage>{emailErrors.email?.message}</FormErrorMessage>
                  </FormControl>

                  <Button
                    type="submit"
                    colorScheme="brand"
                    size="lg"
                    fontSize="md"
                    fontWeight="bold"
                    isLoading={isSendingOTP}
                    loadingText="Sending code..."
                    w="full"
                    _hover={{ transform: 'translateY(-2px)', shadow: 'lg' }}
                    transition="all 0.2s"
                  >
                    Send verification code
                  </Button>

                  <HStack justify="center" spacing={1}>
                    <Text color="gray.600" fontSize="sm">
                      Remember your password?
                    </Text>
                    <Link
                      as={RouterLink}
                      to="/auth/login"
                      color="brand.500"
                      fontWeight="semibold"
                      fontSize="sm"
                      _hover={{ color: 'brand.600', textDecoration: 'underline' }}
                    >
                      Sign in
                    </Link>
                  </HStack>
                </Stack>
              </form>
            ) : (
              // Step 2: OTP and New Password Form
              <form onSubmit={handleSubmitReset(onSubmitReset)}>
                <Stack spacing={6}>
                  {/* Back Button */}
                  <Button
                    leftIcon={<ArrowBackIcon />}
                    variant="ghost"
                    size="sm"
                    onClick={handleBackToStep1}
                    alignSelf="flex-start"
                  >
                    Change email
                  </Button>

                  {/* Email Display */}
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={2}>
                      Verification code sent to:
                    </Text>
                    <Text fontWeight="semibold" color="brand.600">
                      {email}
                    </Text>
                  </Box>

                  {/* OTP Input */}
                  <FormControl>
                    <FormLabel fontWeight="semibold">Verification code</FormLabel>
                    <HStack justify="center" spacing={2}>
                      <PinInput
                        otp
                        size="lg"
                        value={otp}
                        onChange={setOtp}
                        placeholder=""
                        focusBorderColor="brand.500"
                      >
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                        <PinInputField
                          w="45px"
                          h="55px"
                          fontSize="xl"
                          fontWeight="bold"
                          borderRadius="lg"
                          borderWidth="2px"
                        />
                      </PinInput>
                    </HStack>
                  </FormControl>

                  {/* Resend OTP */}
                  <HStack justify="center">
                    {canResend ? (
                      <Button
                        variant="link"
                        colorScheme="brand"
                        size="sm"
                        fontWeight="semibold"
                        onClick={handleResendOTP}
                        isLoading={isSendingOTP}
                      >
                        Resend code
                      </Button>
                    ) : (
                      <Text fontSize="sm" color="gray.500">
                        Resend code in{' '}
                        <Text as="span" fontWeight="semibold" color="brand.500">
                          {countdown}s
                        </Text>
                      </Text>
                    )}
                  </HStack>

                  {/* New Password Field */}
                  <FormControl isInvalid={!!resetErrors.new_password}>
                    <FormLabel htmlFor="new_password" fontWeight="semibold">
                      New password
                    </FormLabel>
                    <InputGroup size="lg">
                      <Input
                        id="new_password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Create a strong password"
                        {...registerReset('new_password')}
                      />
                      <InputRightElement>
                        <IconButton
                          aria-label={showPassword ? 'Hide password' : 'Show password'}
                          icon={showPassword ? <ViewOffIcon /> : <ViewIcon />}
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowPassword(!showPassword)}
                        />
                      </InputRightElement>
                    </InputGroup>
                    <FormErrorMessage>{resetErrors.new_password?.message}</FormErrorMessage>

                    {/* Password Strength Indicator */}
                    {newPassword && (
                      <Box mt={2}>
                        <HStack justify="space-between" mb={1}>
                          <Text fontSize="xs" color="gray.600">
                            Password strength:
                          </Text>
                          <Text
                            fontSize="xs"
                            fontWeight="semibold"
                            color={`${getPasswordStrengthColor(passwordStrength)}.500`}
                          >
                            {getPasswordStrengthText(passwordStrength)}
                          </Text>
                        </HStack>
                        <Progress
                          value={passwordStrength}
                          size="xs"
                          colorScheme={getPasswordStrengthColor(passwordStrength)}
                          borderRadius="full"
                        />
                      </Box>
                    )}

                    {/* Password Requirements */}
                    {newPassword && (
                      <Box mt={3} p={3} bg="gray.50" borderRadius="md">
                        <Text fontSize="xs" fontWeight="semibold" mb={2} color="gray.700">
                          Password must contain:
                        </Text>
                        <List spacing={1}>
                          {passwordRequirements.map((req, index) => (
                            <ListItem key={index} fontSize="xs" color={req.met ? 'green.600' : 'gray.500'}>
                              <ListIcon
                                as={req.met ? CheckCircleIcon : WarningIcon}
                                color={req.met ? 'green.500' : 'gray.400'}
                              />
                              {req.text}
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </FormControl>

                  {/* Confirm Password Field */}
                  <FormControl isInvalid={!!resetErrors.confirmPassword}>
                    <FormLabel htmlFor="confirmPassword" fontWeight="semibold">
                      Confirm new password
                    </FormLabel>
                    <InputGroup size="lg">
                      <Input
                        id="confirmPassword"
                        type={showConfirmPassword ? 'text' : 'password'}
                        placeholder="Re-enter your password"
                        {...registerReset('confirmPassword')}
                      />
                      <InputRightElement>
                        <IconButton
                          aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                          icon={showConfirmPassword ? <ViewOffIcon /> : <ViewIcon />}
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        />
                      </InputRightElement>
                    </InputGroup>
                    <FormErrorMessage>{resetErrors.confirmPassword?.message}</FormErrorMessage>
                  </FormControl>

                  {/* Submit Button */}
                  <Button
                    type="submit"
                    colorScheme="brand"
                    size="lg"
                    fontSize="md"
                    fontWeight="bold"
                    isLoading={isResetting}
                    loadingText="Resetting password..."
                    w="full"
                    isDisabled={otp.length !== 6}
                    _hover={{ transform: 'translateY(-2px)', shadow: 'lg' }}
                    transition="all 0.2s"
                  >
                    Reset password
                  </Button>
                </Stack>
              </form>
            )}
          </Box>

          {/* Back to Login */}
          <HStack justify="center" spacing={1}>
            <Text color="gray.600" fontSize="sm">
              Remember your password?
            </Text>
            <Link
              as={RouterLink}
              to="/auth/login"
              color="brand.500"
              fontWeight="semibold"
              fontSize="sm"
              _hover={{ color: 'brand.600', textDecoration: 'underline' }}
            >
              Sign in
            </Link>
          </HStack>
        </VStack>
      </Container>
    </Box>
  );
};

export default ForgotPasswordPage;
