import React from "react";
import OrderTable from "@/app/components/OrdersTable";
import { Suspense } from "react";
import { getVendorOrders } from "@/app/utils/libs";
import { OrderProp } from "@/types";

const page = async () => {
  const orders = (await getVendorOrders()) as OrderProp[];
  // console.log(orders);
  return (
    <div>
      <Suspense>
        <OrderTable />
      </Suspense>
    </div>
  );
};

export default page;
