import { FormControl, FormLabel, FormErrorMessage, Input, Select, Textarea } from '@chakra-ui/react';
import { UseFormRegisterReturn } from 'react-hook-form';

interface BaseFormFieldProps {
  label: string;
  isRequired?: boolean;
  error?: string;
  helperText?: string;
}

interface InputFormFieldProps extends BaseFormFieldProps {
  type?: 'text' | 'email' | 'password' | 'number' | 'date' | 'tel' | 'file';
  placeholder?: string;
  register: UseFormRegisterReturn;
  defaultValue?: string;
  accept?: string;
  maxLength?: number;
  min?: string | number;
  max?: string | number;
}

interface SelectFormFieldProps extends BaseFormFieldProps {
  register: UseFormRegisterReturn;
  options: Array<{ value: string; label: string }>;
  defaultValue?: string;
  placeholder?: string;
}

interface TextareaFormFieldProps extends BaseFormFieldProps {
  register: UseFormRegisterReturn;
  placeholder?: string;
  defaultValue?: string;
  rows?: number;
}

/**
 * Reusable Input FormField with automatic error display
 */
export const InputFormField = ({
  label,
  isRequired = false,
  error,
  type = 'text',
  placeholder,
  register,
  defaultValue,
  accept,
  maxLength,
  min,
  max,
}: InputFormFieldProps) => {
  return (
    <FormControl isRequired={isRequired} isInvalid={!!error}>
      <FormLabel>{label}</FormLabel>
      <Input
        type={type}
        placeholder={placeholder}
        defaultValue={defaultValue}
        accept={accept}
        maxLength={maxLength}
        min={min}
        max={max}
        {...register}
      />
      {error && <FormErrorMessage>{error}</FormErrorMessage>}
    </FormControl>
  );
};

/**
 * Reusable Select FormField with automatic error display
 */
export const SelectFormField = ({
  label,
  isRequired = false,
  error,
  register,
  options,
  defaultValue,
  placeholder,
}: SelectFormFieldProps) => {
  return (
    <FormControl isRequired={isRequired} isInvalid={!!error}>
      <FormLabel>{label}</FormLabel>
      <Select defaultValue={defaultValue} {...register}>
        {placeholder && <option value="">{placeholder}</option>}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </Select>
      {error && <FormErrorMessage>{error}</FormErrorMessage>}
    </FormControl>
  );
};

/**
 * Reusable Textarea FormField with automatic error display
 */
export const TextareaFormField = ({
  label,
  isRequired = false,
  error,
  register,
  placeholder,
  defaultValue,
  rows = 4,
}: TextareaFormFieldProps) => {
  return (
    <FormControl isRequired={isRequired} isInvalid={!!error}>
      <FormLabel>{label}</FormLabel>
      <Textarea
        placeholder={placeholder}
        defaultValue={defaultValue}
        rows={rows}
        {...register}
      />
      {error && <FormErrorMessage>{error}</FormErrorMessage>}
    </FormControl>
  );
};
