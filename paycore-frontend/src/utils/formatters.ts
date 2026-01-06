import { format, formatDistanceToNow } from 'date-fns';

export const formatCurrency = (amount: number | string | undefined | null, currencyCode: string = 'NGN'): string => {
  const currencySymbols: Record<string, string> = {
    NGN: '₦',
    USD: '$',
    GBP: '£',
    EUR: '€',
    KES: 'KSh',
    GHS: '₵',
  };

  const symbol = currencySymbols[currencyCode] || currencyCode;

  // Handle undefined, null, or invalid values
  if (amount === undefined || amount === null) {
    return `${symbol}0.00`;
  }

  const numAmount = typeof amount === 'string' ? parseFloat(amount) : amount;

  // Handle NaN or invalid numbers
  if (isNaN(numAmount)) {
    return `${symbol}0.00`;
  }

  return `${symbol}${numAmount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
};

export const formatDate = (date: string | Date, formatString: string = 'MMM dd, yyyy'): string => {
  return format(new Date(date), formatString);
};

export const formatDateTime = (date: string | Date): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};

export const formatRelativeTime = (date: string | Date | null | undefined): string => {
  if (!date) return 'N/A';

  const dateObj = new Date(date);

  // Check if the date is invalid
  if (isNaN(dateObj.getTime())) {
    return 'N/A';
  }

  const formatted = formatDistanceToNow(dateObj, { addSuffix: true });

  // Shorten the format: "6 minutes ago" -> "6 m ago"
  return formatted
    .replace(' seconds', ' sec')
    .replace(' second', ' sec')
    .replace(' minutes', ' m')
    .replace(' minute', ' m')
    .replace(' hours', ' h')
    .replace(' hour', ' h')
    .replace(' days', ' d')
    .replace(' day', ' d')
    .replace(' months', ' mo')
    .replace(' month', ' mo')
    .replace(' years', ' y')
    .replace(' year', ' y');
};

export const formatCardNumber = (cardNumber: string): string => {
  return cardNumber.replace(/(\d{4})/g, '$1 ').trim();
};

export const maskCardNumber = (cardNumber: string | undefined): string => {
  if (!cardNumber) return '**** **** **** ****';
  if (cardNumber.length < 4) return cardNumber;
  return cardNumber.slice(0, 4) + ' **** **** ' + cardNumber.slice(-4);
};

export const formatPhoneNumber = (phone: string): string => {
  const cleaned = phone.replace(/\D/g, '');
  const match = cleaned.match(/^(\d{3})(\d{3})(\d{4})$/);
  if (match) {
    return `(${match[1]}) ${match[2]}-${match[3]}`;
  }
  return phone;
};

export const truncateText = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + '...';
};

export const getStatusColor = (status: string): string => {
  const statusColors: Record<string, string> = {
    completed: 'green',
    success: 'green',
    active: 'green',
    approved: 'green',
    pending: 'yellow',
    processing: 'blue',
    failed: 'red',
    error: 'red',
    cancelled: 'gray',
    rejected: 'red',
    blocked: 'red',
    frozen: 'orange',
    suspended: 'orange',
  };

  return statusColors[status.toLowerCase()] || 'gray';
};
