import { z } from "zod";

export const BasicInformationSchema = z.object({
  image_1: z
    .instanceof(File, {
      message: "Image is required and should be a file",
    })
    .refine((file) => file.size <= 10 * 1024 * 1024, {
      message: "Image must be less than 5MB",
    })
    .refine(
      (file) =>
        ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
          file.type
        ),
      { message: "Image must be a JPEG, PNG, or GIF" }
    ),
  title: z
    .string({ required_error: "This field is required" })
    .min(3, "Title is required"),
  description: z
    .string({ required_error: "This field is required" })
    .min(1, "Description is required"),
});

export const PricesSchema = z.object({
  sales_price: z.string().min(1, "Sales price is required"),
  regular_price: z.string().min(1, "Regular price is required"),
  shipping_amount: z.string().min(1, "Shipping amount is required"),
  stock_qty: z.string().min(1, "Stock quantity is required"),
  tag: z.string().min(1, "Tag is required"),
  total_price: z.string().min(1, "Total price is required"),
});
export const CategorySchema = z.object({
  category: z.string().min(1, "Total price is required"),
  brands: z.string().min(1, "Total price is required"),
});
export const GallerySchema = z.object({
  image_2: z
    .instanceof(File, {
      message: "Image is required and should be a file",
    })
    .refine((file) => file.size <= 10 * 1024 * 1024, {
      message: "Image must be less than 5MB",
    })
    .refine(
      (file) =>
        ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
          file.type
        ),
      { message: "Image must be a JPEG, PNG, or GIF" }
    ),
  image_3: z
    .instanceof(File, {
      message: "Image is required and should be a file",
    })
    .refine((file) => file.size <= 10 * 1024 * 1024, {
      message: "Image must be less than 5MB",
    })
    .refine(
      (file) =>
        ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
          file.type
        ),
      { message: "Image must be a JPEG, PNG, or GIF" }
    ),
  image_4: z
    .instanceof(File, {
      message: "Image is required and should be a file",
    })
    .refine((file) => file.size <= 10 * 1024 * 1024, {
      message: "Image must be less than 5MB",
    })
    .refine(
      (file) =>
        ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
          file.type
        ),
      { message: "Image must be a JPEG, PNG, or GIF" }
    ),
  video: z
    .instanceof(File)
    .refine(
      (file) =>
        ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
          file.type
        ),
      { message: "Image must be a JPEG, PNG, or GIF" }
    ),
});
export const SpecificationSchema = z.object({
  specification: z.object({
    title: z.string(),
    content: z.string(),
  }),
});
export const SizesSchema = z.object({
  sizes: z.object({
    size: z.string(),
    price: z.string(),
  }),
});
export const ColorSchema = z.object({
  colors: z.object({
    name: z.string(),
    code: z.string(),
    image: z
      .instanceof(File)
      .refine(
        (file) =>
          ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
            file.type
          ),
        { message: "Image must be a JPEG, PNG, or GIF" }
      ),
  }),
});

const NewProductSchema = z.object({
  ...BasicInformationSchema.shape,
  ...PricesSchema.shape,
  ...CategorySchema.shape,
  ...GallerySchema.shape,
  ...SpecificationSchema.shape,
  ...SizesSchema.shape,
  ...ColorSchema.shape,
});
export type NewProductFieldTypes = z.infer<typeof NewProductSchema>;
