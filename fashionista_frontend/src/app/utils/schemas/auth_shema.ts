import { z } from "zod";

export const signupSchema = z
  .object({
    email: z.string().email("Please provide a valid email address").optional(),
    phone: z
      .string()
      .regex(/^[0-9]{10}$/, { message: "Invalid phone number" })
      .optional(),
    role: z.string(),
    password: z.string().min(7, "password is required"),
    password2: z
      .string({
        required_error: "Confirm password is required",
        invalid_type_error: "Confirm password should be a string",
      })
      .min(1, "confirm password is required"),
  })
  .refine((data) => data.email || data.phone, {
    message: "Either email or phone number must be provided",
  })
  .refine((data) => !(data.email && data.phone), {
    message: "Only one of email or phone number should be provided",
  })
  .refine((data) => data.password === data.password2, {
    message: "Passwords don't match",
    path: ["password1"],
  });
