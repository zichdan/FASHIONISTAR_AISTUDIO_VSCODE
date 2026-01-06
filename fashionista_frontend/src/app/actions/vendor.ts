"use server";
import { object, z } from "zod";
import { FormSchema, PricesSchema } from "../utils/schema";
import { fetchWithAuth } from "../utils/fetchAuth";
import {
  BasicInformationSchema,
  CategorySchema,
  GallerySchema,
  SizesSchema,
  SpecificationSchema,
} from "../utils/schemas/addProduct";
import { redirect } from "next/navigation";
// const schema = z.object({
//   image_1: z
//     .instanceof(File, {
//       message: "Image is required and should be a file",
//     })
//     .refine((file) => file.size <= 10 * 1024 * 1024, {
//       message: "Image must be less than 5MB",
//     }) // 5MB limit
//     .refine(
//       (file) =>
//         ["image/jpeg", "image/jpg", "image/png", "image/gif"].includes(
//           file.type
//         ),
//       { message: "Image must be a JPEG, PNG, or GIF" }
//     ),
//   title: z.string().min(3, "Product title is required "),
//   discription: z.string().min(10, "Product description is required"),
// });
export const BasicInformationAction = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  const validated = BasicInformationSchema.safeParse(data);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=prices");
};
export const PricesAction = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  const validated = PricesSchema.safeParse(data);
  if (!validated.success) {
    console.log(validated.error.flatten().fieldErrors);
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=category");
};
export const CategoryAction = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  const validated = CategorySchema.safeParse(data);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=gallery");
};
export const GalleryAction = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  const validated = GallerySchema.safeParse(data);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=specification");
};
export const SpecificationAction = async (prev: any, formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());

  const specData = { specification: data };
  const validated = SpecificationSchema.safeParse(specData);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=sizes");
};
export const SizesAction = async (prev: any, formdata: FormData) => {
  const newData = {
    sizes: {
      size: formdata.get("size"),
      price: formdata.get("size_price"),
    },
  };
  console.log(newData);
  const validated = SizesSchema.safeParse(newData);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  redirect("/dashboard/products?step=color");
};

export const newProduct = async (formdata: FormData | object) => {
  // const data = Object.fromEntries(formdata.entries());
  // console.log("form information", data);
  // const validatedForm = FormSchema.safeParse(data);
  // if (!validatedForm.success) {
  //   return {
  //     errors: validatedForm.error.flatten().fieldErrors,
  //   };
  // }
  // try {
  //   const res = await fetchWithAuth(
  //     "/vendor/product-create",
  //     "post",
  //     data,
  //     "multipart/formdata"
  //   );
  //   console.log(res);
  //   return { message: "New Product created Successfully" };
  // } catch (error) {
  //   console.log(error);
  //   return {
  //     call_errors: "There was an error while trying to create this product",
  //   };
  // }
};
export const deleteProduct = async (vendor_id: string, product_id: string) => {
  try {
    const res = await fetchWithAuth(
      `/vendor/product-delete/${vendor_id}/${product_id}`,
      "delete"
    );
    console.log(res);
  } catch (error) {
    console.log(error);
  }
};

export const editProduct = async () => {};
