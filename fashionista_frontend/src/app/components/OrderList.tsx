"use client";
import React from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { OrderProp } from "@/types";

interface OrderListProps {
  orders: OrderProp[];
}

const OrderList: React.FC<OrderListProps> = ({ orders }) => {
  const searchParams = useSearchParams();
  const order_status = searchParams.get("order-status");
  const filteredOrders = order_status
    ? orders.filter((order) => order.order_status === order_status)
    : orders;

  const orderItems = filteredOrders.map((item) => (
    <tr
      key={item.id}
      className="align-top text-center box_shadow md:text-[15px] md:leading-5 text-[7px] leading-[9px] text-black"
    >
      <td className="pl-2 py-4 flex justify-end">
        <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
      </td>
      <td className="py-5">
        <Link href={`/orders/${item.id}`}>{item.id}</Link>
      </td>
      <td className="py-5">{item.date}</td>
      <td className="py-5">{item.customer_name}</td>
      <td className="py-5">{item.address.substring(0, 10)}</td>
      <td className="py-5 px-2 text-[5px] md:text-xs ">
        <div
          className={`w-fit mx-auto flex justify-center items-center gap-1 md:gap-2.5 py-2 md:px-3 px-1 rounded-[40px] ${
            item.payment_status == "Paid"
              ? "bg-[#EDFAF3] text-[#25784A] "
              : "bg-[#FDFAE4] text-[#F1D858]"
          } `}
        >
          <span
            className={`w-1 h-1 md:w-2.5 md:h-2.5 rounded-full ${
              item.payment_status == "Paid" ? "bg-[#25784A]" : "bg-[#F1D858]"
            }`}
          />
          {item.payment_status}
        </div>
      </td>
      <td className="text-black py-5">{item.order_status}</td>
      <td className="text-black py-5">
        {item.items}
        <span className="px-1">items</span>
      </td>
    </tr>
  ));

  return (
    <div className="space-y-6">
      <nav className="w-full lg:w-[55%] flex justify-between items-center font-satoshi font-medium">
        <Link
          href="/admin-dashboard"
          shallow={true}
          className={`grow-0 order-[0] hover:bg-[#fda600] hover:text-black text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
            !order_status
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#9d9d9d]"
          }`}
        >
          All({orders.length})
        </Link>
        <Link
          href="/admin-dashboard?order-status=pending"
          shallow={true}
          className={`grow-0 order-[0] hover:bg-[#fda600] hover:text-black text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
            order_status === "pending"
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#9d9d9d]"
          }`}
        >
          Pending
        </Link>
        <Link
          href="/admin-dashboard?order-status=ready-to-deliver"
          shallow={true}
          className={`grow-0 order-[0] hover:bg-[#fda600] hover:text-black text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
            order_status === "ready-to-deliver"
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#9d9d9d]"
          }`}
        >
          Ready to deliver
        </Link>
        <Link
          href="/admin-dashboard?order-status=delivered"
          shallow={true}
          className={`grow-0 order-[0] hover:bg-[#fda600] hover:text-black text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
            order_status === "delivered"
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#9d9d9d]"
          }`}
        >
          Delivered
        </Link>
        <Link
          href="/admin-dashboard?order-status=returned"
          shallow={true}
          className={`grow-0 order-[0] hover:bg-[#fda600] hover:text-black text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
            order_status === "returned"
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#9d9d9d]"
          }`}
        >
          Returned
        </Link>
      </nav>
      <div className="p-2.5 bg-white shadow-card_shadow rounded min-h-[200px]">
        <table className="min-w-full divide-y divide-gray-200 table-fixed text-black font-satoshi">
          <thead>
            <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-sm">
              <th className="pl-2 py-4 flex justify-end">
                <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
              </th>
              <th className="py-3 px-1 text-center">ID</th>
              <th className="py-3 px-1 text-center">Date</th>
              <th className="py-3 px-1 text-center">Customer Name</th>
              <th className="py-3 px-1 text-center">Address</th>
              <th className="py-3 px-1 text-center">Payment Status</th>
              <th className="py-3 px-1 text-center">Order Status</th>
              <th className="py-3 px-1 text-center">Items</th>
            </tr>
          </thead>
          <tbody className="align-top">{orderItems}</tbody>
        </table>
      </div>
    </div>
  );
};

export default OrderList;
