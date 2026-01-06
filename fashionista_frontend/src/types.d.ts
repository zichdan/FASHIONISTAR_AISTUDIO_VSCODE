import { z } from "zod";
import { FormSchema } from "./app/utils/schema";
import { signupSchema } from "./app/utils/schemas/auth_shema";

interface CardProps {
  image: string;
  title: string;
  vendor: string;
  rating: number;
  price: number;
}

// interface NewProductType{
//     image_1: File,
//     title: string,
//     description: string,
//     sales_price: string,
//     regular_price: string,
//     shipping_amount: string,
//     stock_qty: string,
//     tag: string,
//     total_price: string,
//     category: string,
//     brands: string,
//     image_2: File,
//     image_3: File,
// }
type NewProductType = z.infer<typeof FormSchema>;

type SignUpProps = z.infer<typeof signupSchema>;

interface OrderProp {
  id: number;
  date: string;
  customer_name: string;
  address: string;
  payment_status: "Paid" | "pending" | "failed";
  order_status:
    | "pending"
    | "fulfilled"
    | "ready-to-deliver"
    | "delivered"
    | "returned";
  items: number;
}
type PageProps = {
  params: { [key: string]: string | string[] | undefined };
  searchParams: { [key: string]: string | string[] | undefined };
};

interface CollectionsProps {
  id: string;
  image: string;
  rating: number;
  title: string;
  price: string;
}
// interface VendorProps {
//   id: number;
//   image: string;
//   name: string;
//   email: string;
//   description: string;
//   mobile: string;
//   verified?: boolean;
//   active?: boolean;
//   balance?: string;
//   vid?: string;
//   date?: string;
//   slug: string;
// }
interface VendorProp {
  id: string;
  image: string;
  name: string;
  rating: number;
  address: string;
  mobile: string;
  slug: string;
}
