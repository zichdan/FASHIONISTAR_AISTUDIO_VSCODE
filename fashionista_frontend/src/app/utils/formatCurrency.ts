export const formatCurrency = (value: string | number) => {
  // Using NGN symbol directly as toLocaleString might not support "NGN" in all environments
  return `₦${value.toLocaleString("en-US")}`;
};
