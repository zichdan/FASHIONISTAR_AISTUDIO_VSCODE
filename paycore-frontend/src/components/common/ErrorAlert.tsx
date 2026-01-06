import { Alert, AlertIcon, AlertTitle, AlertDescription, CloseButton, Box } from '@chakra-ui/react';

interface ErrorAlertProps {
  title?: string;
  message: string;
  onClose?: () => void;
}

export const ErrorAlert = ({ title = 'Error', message, onClose }: ErrorAlertProps) => {
  return (
    <Alert status="error" borderRadius="lg">
      <AlertIcon />
      <Box flex="1">
        <AlertTitle>{title}</AlertTitle>
        <AlertDescription display="block">{message}</AlertDescription>
      </Box>
      {onClose && <CloseButton position="absolute" right="8px" top="8px" onClick={onClose} />}
    </Alert>
  );
};
