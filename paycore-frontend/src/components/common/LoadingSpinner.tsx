import { Spinner, Center, SpinnerProps } from '@chakra-ui/react';

interface LoadingSpinnerProps extends SpinnerProps {
  fullScreen?: boolean;
}

export const LoadingSpinner = ({ fullScreen = false, ...props }: LoadingSpinnerProps) => {
  if (fullScreen) {
    return (
      <Center h="100vh">
        <Spinner size="xl" color="brand.500" thickness="4px" {...props} />
      </Center>
    );
  }

  return <Spinner color="brand.500" {...props} />;
};
