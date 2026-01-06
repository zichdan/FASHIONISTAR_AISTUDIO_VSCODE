import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  HStack,
  Card,
  CardBody,
  Button,
  Badge,
  Icon,
  Avatar,
  useDisclosure,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Select,
  useToast,
  Skeleton,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  SimpleGrid,
  Divider,
  Progress,
  Switch,
} from '@chakra-ui/react';
import {
  FiUser,
  FiEdit,
  FiCamera,
  FiMail,
  FiPhone,
  FiMapPin,
  FiShield,
  FiCheckCircle,
  FiAlertCircle,
} from 'react-icons/fi';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import {
  useGetProfileQuery,
  useUpdateProfileMutation,
  useUploadAvatarMutation,
  useGetCountriesQuery,
} from '@/features/profile/services/profileApi';
import {
  useSubmitKYCMutation,
} from '@/features/compliance/services/complianceApi';
import { formatDate } from '@/utils/formatters';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ErrorAlert } from '@/components/common/ErrorAlert';
import { handleApiError } from '@/utils/formErrorHandler';

interface ProfileForm {
  first_name: string;
  last_name: string;
  dob: string;
  bio: string;
  phone: string;
  push_enabled: boolean;
  in_app_enabled: boolean;
  email_enabled: boolean;
  biometrics_enabled: boolean;
  avatar?: FileList;
}

interface KYCForm {
  level: string;
  first_name: string;
  last_name: string;
  middle_name?: string;
  date_of_birth: string;
  nationality: string;
  address_line_1: string;
  address_line_2?: string;
  city: string;
  state: string;
  postal_code: string;
  country_id: string;
  document_type: string;
  document_number: string;
  document_expiry_date?: string;
  document_issuing_country_id: string;
  notes?: string;
  id_document: File | null;
  selfie: File | null;
  proof_of_address: File | null;
}

export const ProfilePage = () => {
  const toast = useToast();
  const [avatarFile, setAvatarFile] = useState<File | null>(null);

  const { isOpen: isEditOpen, onOpen: onEditOpen, onClose: onEditClose } = useDisclosure();
  const { isOpen: isKYCOpen, onOpen: onKYCOpen, onClose: onKYCClose } = useDisclosure();

  const profileForm = useForm<ProfileForm>();
  const kycForm = useForm<any>();

  const { data: profileData, isLoading, error, refetch: refetchProfile } = useGetProfileQuery();
  const { data: countriesData } = useGetCountriesQuery();
  const [updateProfile, { isLoading: updating }] = useUpdateProfileMutation();
  const [uploadAvatar, { isLoading: uploading }] = useUploadAvatarMutation();
  const [submitKYC, { isLoading: submittingKYC }] = useSubmitKYCMutation();

  // KYC countdown state
  const [showKYCCountdown, setShowKYCCountdown] = useState(false);
  const [kycCountdown, setKycCountdown] = useState(35);
  const [kycProgress, setKycProgress] = useState(0);

  const profile = profileData?.data;
  const countries = countriesData?.data || [];
  const kycLevel = profile?.kyc_level || 'TIER_0';

  // KYC countdown effect
  useEffect(() => {
    if (showKYCCountdown && kycCountdown > 0) {
      const timer = setTimeout(() => {
        setKycCountdown(kycCountdown - 1);
        setKycProgress(((35 - kycCountdown + 1) / 35) * 100);
      }, 1000);
      return () => clearTimeout(timer);
    } else if (showKYCCountdown && kycCountdown === 0) {
      // Reload profile data after countdown
      refetchProfile();
      setShowKYCCountdown(false);
      setKycCountdown(35);
      setKycProgress(0);
      toast({
        title: 'KYC Verification Complete',
        description: 'Your KYC has been processed and approved!',
        status: 'success',
        duration: 5000,
      });
    }
  }, [showKYCCountdown, kycCountdown, refetchProfile, toast]);

  const handleEditProfile = async (data: ProfileForm) => {
    try {
      // Create FormData for multipart upload
      const formData = new FormData();
      formData.append('first_name', data.first_name);
      formData.append('last_name', data.last_name);
      formData.append('dob', data.dob);
      formData.append('bio', data.bio || '');
      formData.append('phone', data.phone);
      formData.append('push_enabled', String(data.push_enabled ?? true));
      formData.append('in_app_enabled', String(data.in_app_enabled ?? true));
      formData.append('email_enabled', String(data.email_enabled ?? true));
      formData.append('biometrics_enabled', String(data.biometrics_enabled ?? false));

      // Add avatar if selected
      if (data.avatar && data.avatar.length > 0) {
        formData.append('avatar', data.avatar[0]);
      }

      await updateProfile(formData as any).unwrap();
      toast({ title: 'Profile updated successfully', status: 'success', duration: 3000 });
      onEditClose();
      profileForm.reset();
    } catch (error: any) {
      handleApiError(error, profileForm.setError, toast);
    }
  };

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      await uploadAvatar(file).unwrap();
      toast({ title: 'Avatar updated successfully', status: 'success' });
    } catch (error: any) {
      toast({ title: 'Upload failed', description: error.data?.message, status: 'error' });
    }
  };

  const handleKYCSubmit = async (data: any) => {
    const formData = {
      ...data,
      documents: {
        id_document: data.id_document[0],
        selfie: data.selfie[0],
        proof_of_address: data.proof_of_address?.[0],
      },
    };

    try {
      await submitKYC(formData).unwrap();
      toast({
        title: 'KYC submitted successfully',
        description: 'Your verification will be processed in 35 seconds',
        status: 'success',
        duration: 5000,
      });
      onKYCClose();
      kycForm.reset();

      // Start countdown timer
      setShowKYCCountdown(true);
      setKycCountdown(35);
      setKycProgress(0);
    } catch (error: any) {
      handleApiError(error, kycForm.setError, toast);
    }
  };

  const openEditModal = () => {
    if (profile) {
      profileForm.reset({
        first_name: profile.first_name,
        last_name: profile.last_name,
        dob: profile.dob || '',
        bio: profile.bio || '',
        phone: profile.phone || '',
        push_enabled: profile.push_enabled ?? true,
        in_app_enabled: profile.in_app_enabled ?? true,
        email_enabled: profile.email_enabled ?? true,
        biometrics_enabled: profile.biometrics_enabled ?? false,
      });
    }
    onEditOpen();
  };

  const getKYCProgress = () => {
    const levels = ['TIER_0', 'TIER_1', 'TIER_2', 'TIER_3'];
    const currentIndex = levels.indexOf(kycLevel.toUpperCase());
    return ((currentIndex + 1) / levels.length) * 100;
  };

  if (isLoading) {
    return (
      <Container maxW="container.xl" py={8}>
        <VStack spacing={6} align="stretch">
          <Skeleton height="200px" borderRadius="xl" />
          <Skeleton height="400px" borderRadius="xl" />
        </VStack>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxW="container.xl" py={8}>
        <ErrorAlert message="Failed to load profile. Please try again." />
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={8} align="stretch">
        {/* KYC Processing Countdown */}
        {showKYCCountdown && (
          <Card bg="blue.50" borderColor="blue.200" borderWidth={2}>
            <CardBody>
              <VStack spacing={4}>
                <HStack justify="space-between" w="full">
                  <VStack align="start" spacing={1}>
                    <Heading size="sm" color="blue.700">
                      Processing Your KYC Verification
                    </Heading>
                    <Text fontSize="sm" color="blue.600">
                      Your verification will be completed in {kycCountdown} seconds
                    </Text>
                  </VStack>
                  <Text fontSize="3xl" fontWeight="bold" color="blue.700">
                    {kycCountdown}s
                  </Text>
                </HStack>
                <Box w="full">
                  <Progress
                    value={kycProgress}
                    size="lg"
                    colorScheme="blue"
                    borderRadius="full"
                    hasStripe
                    isAnimated
                  />
                  <Text fontSize="xs" color="blue.600" mt={1} textAlign="center">
                    {Math.round(kycProgress)}% Complete
                  </Text>
                </Box>
              </VStack>
            </CardBody>
          </Card>
        )}

        {/* Profile Header */}
        <Card>
          <CardBody>
            <HStack spacing={6} align="start">
              <Box position="relative">
                <Avatar size="2xl" name={`${profile?.first_name} ${profile?.last_name}`} src={profile?.avatar_url} />
                <Button
                  size="sm"
                  position="absolute"
                  bottom={0}
                  right={0}
                  borderRadius="full"
                  colorScheme="brand"
                  as="label"
                  cursor="pointer"
                  isLoading={uploading}
                >
                  <Icon as={FiCamera} />
                  <input type="file" hidden accept="image/*" onChange={handleAvatarUpload} />
                </Button>
              </Box>
              <VStack align="start" flex={1} spacing={3}>
                <HStack>
                  <Heading size="lg">
                    {profile?.first_name} {profile?.last_name}
                  </Heading>
                  {profile?.is_verified && <Icon as={FiCheckCircle} color="green.500" boxSize={5} />}
                </HStack>
                <VStack align="start" spacing={1}>
                  <HStack>
                    <Icon as={FiMail} color="gray.500" />
                    <Text color="gray.600">{profile?.email}</Text>
                  </HStack>
                  {profile?.phone && (
                    <HStack>
                      <Icon as={FiPhone} color="gray.500" />
                      <Text color="gray.600">{profile.phone}</Text>
                    </HStack>
                  )}
                  {profile?.bio && (
                    <HStack>
                      <Icon as={FiUser} color="gray.500" />
                      <Text color="gray.600">{profile.bio}</Text>
                    </HStack>
                  )}
                </VStack>
                <HStack spacing={2}>
                  <Button size="sm" leftIcon={<Icon as={FiEdit} />} onClick={openEditModal}>
                    Edit Profile
                  </Button>
                </HStack>
              </VStack>
            </HStack>
          </CardBody>
        </Card>

        {/* KYC Status */}
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiShield} boxSize={6} color="brand.500" />
                  <Heading size="md">KYC Verification</Heading>
                </HStack>
                <Badge colorScheme={kycLevel === 'tier_3' ? 'green' : 'yellow'} fontSize="md" px={3} py={1}>
                  {kycLevel.toUpperCase()}
                </Badge>
              </HStack>

              <Box>
                <HStack justify="space-between" mb={2}>
                  <Text fontSize="sm" color="gray.600">
                    Verification Progress
                  </Text>
                  <Text fontSize="sm" fontWeight="600">
                    {Math.round(getKYCProgress())}%
                  </Text>
                </HStack>
                <Progress value={getKYCProgress()} colorScheme="brand" borderRadius="full" />
              </Box>

              {kycLevel !== 'tier_3' && (
                <Button colorScheme="brand" onClick={onKYCOpen}>
                  Upgrade Verification Level
                </Button>
              )}
            </VStack>
          </CardBody>
        </Card>

        {/* Profile Information */}
        <Card>
          <CardBody>
            <Heading size="md" mb={4}>
              Personal Information
            </Heading>
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
              <Box>
                <Text fontSize="sm" color="gray.600" mb={1}>
                  First Name
                </Text>
                <Text fontWeight="600">{profile?.first_name || 'Not set'}</Text>
              </Box>
              <Box>
                <Text fontSize="sm" color="gray.600" mb={1}>
                  Last Name
                </Text>
                <Text fontWeight="600">{profile?.last_name || 'Not set'}</Text>
              </Box>
              <Box>
                <Text fontSize="sm" color="gray.600" mb={1}>
                  Date of Birth
                </Text>
                <Text fontWeight="600">
                  {profile?.dob ? formatDate(profile.dob) : 'Not set'}
                </Text>
              </Box>
              <Box>
                <Text fontSize="sm" color="gray.600" mb={1}>
                  Phone Number
                </Text>
                <Text fontWeight="600">{profile?.phone || 'Not set'}</Text>
              </Box>
              <Box gridColumn={{ md: 'span 2' }}>
                <Text fontSize="sm" color="gray.600" mb={1}>
                  Bio
                </Text>
                <Text fontWeight="600">{profile?.bio || 'Not set'}</Text>
              </Box>
            </SimpleGrid>
          </CardBody>
        </Card>
      </VStack>

      {/* Edit Profile Modal */}
      <Modal isOpen={isEditOpen} onClose={onEditClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={profileForm.handleSubmit(handleEditProfile)}>
            <ModalHeader>Edit Profile</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4} align="stretch">
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl isRequired isInvalid={!!profileForm.formState.errors.first_name}>
                    <FormLabel>First Name</FormLabel>
                    <Input {...profileForm.register('first_name')} />
                    <FormErrorMessage>{profileForm.formState.errors.first_name?.message as string}</FormErrorMessage>
                  </FormControl>
                  <FormControl isRequired isInvalid={!!profileForm.formState.errors.last_name}>
                    <FormLabel>Last Name</FormLabel>
                    <Input {...profileForm.register('last_name')} />
                    <FormErrorMessage>{profileForm.formState.errors.last_name?.message as string}</FormErrorMessage>
                  </FormControl>
                  <FormControl isRequired isInvalid={!!profileForm.formState.errors.phone}>
                    <FormLabel>Phone Number</FormLabel>
                    <Input {...profileForm.register('phone')} placeholder="+2348012345678" />
                    <FormErrorMessage>{profileForm.formState.errors.phone?.message as string}</FormErrorMessage>
                  </FormControl>
                  <FormControl isRequired isInvalid={!!profileForm.formState.errors.dob}>
                    <FormLabel>Date of Birth</FormLabel>
                    <Input type="date" {...profileForm.register('dob')} />
                    <FormErrorMessage>{profileForm.formState.errors.dob?.message as string}</FormErrorMessage>
                  </FormControl>
                </SimpleGrid>

                <FormControl isRequired isInvalid={!!profileForm.formState.errors.bio}>
                  <FormLabel>Bio</FormLabel>
                  <Input {...profileForm.register('bio')} placeholder="Tell us about yourself" maxLength={200} />
                  <FormErrorMessage>{profileForm.formState.errors.bio?.message as string}</FormErrorMessage>
                </FormControl>

                <FormControl isInvalid={!!profileForm.formState.errors.avatar}>
                  <FormLabel>Profile Picture</FormLabel>
                  <Input type="file" accept="image/*" {...profileForm.register('avatar')} />
                  <FormErrorMessage>{profileForm.formState.errors.avatar?.message as string}</FormErrorMessage>
                </FormControl>

                <Divider />

                <Heading size="sm">Notification Preferences</Heading>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl display="flex" alignItems="center">
                    <FormLabel mb={0} flex={1}>Push Notifications</FormLabel>
                    <Switch {...profileForm.register('push_enabled')} />
                  </FormControl>
                  <FormControl display="flex" alignItems="center">
                    <FormLabel mb={0} flex={1}>In-App Notifications</FormLabel>
                    <Switch {...profileForm.register('in_app_enabled')} />
                  </FormControl>
                  <FormControl display="flex" alignItems="center">
                    <FormLabel mb={0} flex={1}>Email Notifications</FormLabel>
                    <Switch {...profileForm.register('email_enabled')} />
                  </FormControl>
                  <FormControl display="flex" alignItems="center">
                    <FormLabel mb={0} flex={1}>Biometric Authentication</FormLabel>
                    <Switch {...profileForm.register('biometrics_enabled')} />
                  </FormControl>
                </SimpleGrid>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onEditClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={updating}>
                Save Changes
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

      {/* KYC Submission Modal */}
      <Modal isOpen={isKYCOpen} onClose={onKYCClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <form onSubmit={kycForm.handleSubmit(handleKYCSubmit)}>
            <ModalHeader>Submit KYC Verification</ModalHeader>
            <ModalCloseButton />
            <ModalBody maxH="70vh" overflowY="auto">
              <VStack spacing={4} align="stretch">
                <FormControl isRequired isInvalid={!!kycForm.formState.errors.level}>
                  <FormLabel>Verification Level</FormLabel>
                  <Select {...kycForm.register('level')}>
                    <option value="">Select Level</option>
                    <option value="tier_1">Tier 1 - Basic</option>
                    <option value="tier_2">Tier 2 - Intermediate</option>
                    <option value="tier_3">Tier 3 - Advanced</option>
                  </Select>
                  <FormErrorMessage>{kycForm.formState.errors.level?.message as string}</FormErrorMessage>
                </FormControl>

                <Divider />

                <Text fontSize="sm" fontWeight="600" color="gray.700">
                  Personal Information
                </Text>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>First Name</FormLabel>
                    <Input {...kycForm.register('first_name')} defaultValue={profile?.first_name} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Last Name</FormLabel>
                    <Input {...kycForm.register('last_name')} defaultValue={profile?.last_name} />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Middle Name (Optional)</FormLabel>
                    <Input {...kycForm.register('middle_name')} />
                  </FormControl>
                  <FormControl isRequired isInvalid={!!kycForm.formState.errors.date_of_birth}>
                    <FormLabel>Date of Birth</FormLabel>
                    <Input type="date" {...kycForm.register('date_of_birth')} defaultValue={profile?.date_of_birth} />
                    <FormErrorMessage>{kycForm.formState.errors.date_of_birth?.message as string}</FormErrorMessage>
                  </FormControl>
                  <FormControl isRequired isInvalid={!!kycForm.formState.errors.nationality}>
                    <FormLabel>Nationality (ISO Code)</FormLabel>
                    <Input {...kycForm.register('nationality')} placeholder="e.g., US, GB, NG" maxLength={2} />
                    <FormErrorMessage>{kycForm.formState.errors.nationality?.message as string}</FormErrorMessage>
                  </FormControl>
                </SimpleGrid>

                <Divider />

                <Text fontSize="sm" fontWeight="600" color="gray.700">
                  Address Information
                </Text>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl isRequired gridColumn={{ md: 'span 2' }}>
                    <FormLabel>Address Line 1</FormLabel>
                    <Input {...kycForm.register('address_line_1')} defaultValue={profile?.address_line_1} />
                  </FormControl>
                  <FormControl gridColumn={{ md: 'span 2' }}>
                    <FormLabel>Address Line 2 (Optional)</FormLabel>
                    <Input {...kycForm.register('address_line_2')} defaultValue={profile?.address_line_2} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>City</FormLabel>
                    <Input {...kycForm.register('city')} defaultValue={profile?.city} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>State</FormLabel>
                    <Input {...kycForm.register('state')} defaultValue={profile?.state} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Postal Code</FormLabel>
                    <Input {...kycForm.register('postal_code')} defaultValue={profile?.postal_code} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Country</FormLabel>
                    <Select {...kycForm.register('country_id')}>
                      <option value="">Select Country</option>
                      {countries.map((country: any) => (
                        <option key={country.id} value={country.id}>
                          {country.name}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                </SimpleGrid>

                <Divider />

                <Text fontSize="sm" fontWeight="600" color="gray.700">
                  Identity Document
                </Text>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>Document Type</FormLabel>
                    <Select {...kycForm.register('document_type')}>
                      <option value="">Select Document Type</option>
                      <option value="national_id">National ID</option>
                      <option value="passport">Passport</option>
                      <option value="drivers_license">Driver's License</option>
                    </Select>
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Document Number</FormLabel>
                    <Input {...kycForm.register('document_number')} />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Document Expiry Date (Optional)</FormLabel>
                    <Input type="date" {...kycForm.register('document_expiry_date')} />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Issuing Country</FormLabel>
                    <Select {...kycForm.register('document_issuing_country_id')}>
                      <option value="">Select Country</option>
                      {countries.map((country: any) => (
                        <option key={country.id} value={country.id}>
                          {country.name}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                </SimpleGrid>

                <Divider />

                <Text fontSize="sm" fontWeight="600" color="gray.700">
                  Document Uploads
                </Text>
                <VStack spacing={4} align="stretch">
                  <FormControl isRequired>
                    <FormLabel>ID Document</FormLabel>
                    <Input type="file" {...kycForm.register('id_document')} accept="image/*,application/pdf" />
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      Upload a clear photo or scan of your identity document
                    </Text>
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Selfie</FormLabel>
                    <Input type="file" {...kycForm.register('selfie')} accept="image/*" />
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      Upload a recent photo of yourself holding your ID document
                    </Text>
                  </FormControl>
                  <FormControl>
                    <FormLabel>Proof of Address (Optional for Tier 1)</FormLabel>
                    <Input type="file" {...kycForm.register('proof_of_address')} accept="image/*,application/pdf" />
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      Upload a utility bill, bank statement, or government document showing your address
                    </Text>
                  </FormControl>
                </VStack>

                <Divider />

                <FormControl>
                  <FormLabel>Additional Notes (Optional)</FormLabel>
                  <Input {...kycForm.register('notes')} placeholder="Any additional information..." />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onKYCClose}>
                Cancel
              </Button>
              <Button colorScheme="brand" type="submit" isLoading={submittingKYC}>
                Submit for Verification
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>
    </Container>
  );
};
