"use server";

import { fetchWithAuth } from "../utils/fetchAuth";

export const getClientOrders = async () => {
  try {
    const orders = await fetchWithAuth("/client/orders");
    console.log(orders);
    return orders.data;
  } catch (error) {
    console.log(error);
  }
};
export const trackOrder = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  // Validate here
  try {
    const tracking = await fetchWithAuth(
      `/client/order/tracking/${data?.order_id}`
    );
    console.log(tracking);
  } catch (error) {}
};
