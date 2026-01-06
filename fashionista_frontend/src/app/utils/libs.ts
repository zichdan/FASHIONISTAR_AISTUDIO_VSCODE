import { fetchWithAuth } from "./fetchAuth";
import { vendor } from "./mock";
import { axiosInstance } from "./axiosInstance";
import { VendorProp } from "@/types";

export const getVendor = async () => {
  try {
    const vendor = await fetchWithAuth("/vendor/dashboard");
    return vendor;
  } catch (error) {
    console.log(vendor);
  }
};

export const getVendorOrders = async () => {
  try {
    const orders = await fetchWithAuth("/vendor/orders/");
    return orders;
  } catch (error) {
    console.log(error);
  }
};
export const getSingleOrder = async (order_oid: string) => {
  try {
    const order = await fetchWithAuth(`/vendor/orders/${order_oid}`);
    return order;
  } catch (error) {
    console.log(error);
  }
};

export const orderAcceptReject = async (
  order_oid: string,
  data: { notification_type: string }
) => {
  try {
    const res = await fetchWithAuth(`/vendor/orders/${order_oid}`, "get", data);
  } catch (error) {
    console.log(error);
  }
};
// Unprotected list of vendors
export const getAllProducts = async () => {
  try {
    const products = await fetchWithAuth("/vendor/products");
    return products;
  } catch (error) {
    console.log(error);
  }
};
export const createNewProduct = async (formdata: object | FormData) => {
  try {
    const res = await fetchWithAuth("/vendor/product-create", "post", formdata);
    // console.log(res);
  } catch (error) {
    console.log(error);
  }
};
export const getAllVendors = async () => {
  try {
    const vendors = await axiosInstance("/vendors/");
    return vendors.data as VendorProp[];
    // console.log(vendors);
  } catch (error) {
    console.log(error);
  }
};
