"use client";
import React from "react";
import TopBanner from "./TopBanner";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

const orders = [
  {
    id: 1,
    date: "April 2, 2024",
    customer_name: "Adam Smith",
    address: "some where on earth",
    payment_status: "Payment pending",
    order_status: "pending",
    items: 4,
  },
  {
    id: 2,
    date: "April 20, 2024",
    customer_name: "Adam Smith",
    address: "some where on earth",
    payment_status: "Paid",
    order_status: "delivered",
    items: 7,
  },
  {
    id: 3,
    date: "April 2, 2024",
    customer_name: "Adam Smith",
    address: "some where on earth",
    payment_status: "Payment pending",
    order_status: "returned",
    items: 1,
  },
  {
    id: 4,
    date: "May 12, 2024",
    customer_name: "Michael Atafor",
    address: "some where on earth",
    payment_status: "Paid",
    order_status: "pending",
    items: 10,
  },
];

const OrderTable = () => {
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
      <td className="py-2">
        <Link href={`/orders/${item.id}`}>{item.id}</Link>
      </td>
      <td className="py-2">{item.date}</td>
      <td className="py-2">{item.customer_name}</td>
      <td className="py-2">{item.address.substring(0, 10)}</td>
      <td className="py-2 px-2 text-[5px] md:text-xs ">
        <div
          className={`w-fit mx-auto flex justify-center items-center gap-1 md:gap-2.5 py-[5px] md:px-3 px-1 rounded-[40px] ${
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
      <td
        className=" 
      text-black py-2"
      >
        {item.order_status}
      </td>
      <td
        className=" 
      text-black py-2"
      >
        {item.items}
      </td>
    </tr>
  ));

  return (
    <div className="flex flex-col gap-10">
      <TopBanner title="Orders" />
      <div className="px-5 md:px-10 space-y-10">
        <h2 className="md:hidden font-satoshi font-medium text-xl text-black pt-6">
          Orders
        </h2>
        <div className="flex items-center w-[60%] h-10 md:w-1/3 md:h-[60px] bg-white border border-[#d9d9d9] px-4 gap-6 rounded-[5px]">
          <span className="block transition-all peer-focus:hidden">
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M13.125 13.125L16.5 16.5"
                stroke="#282828"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M15 8.25C15 4.52208 11.978 1.5 8.25 1.5C4.52208 1.5 1.5 4.52208 1.5 8.25C1.5 11.978 4.52208 15 8.25 15C11.978 15 15 11.978 15 8.25Z"
                stroke="#282828"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <input
            type="search"
            placeholder="Search order ID"
            className="w-full h-full bg-inherit outline-none focus:outline-none peer"
          />
        </div>
        <div className="space-y-6">
          <nav className="w-full lg:w-[55%] flex justify-between items-center font-satoshi font-medium">
            <Link
              href="/orders"
              className={`grow-0 order-[0] text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
                !order_status
                  ? "bg-[#fda600] text-black"
                  : "bg-[#d9d9d9] text-[#9d9d9d]"
              }`}
            >
              All({orders.length})
            </Link>
            <Link
              href="/orders?order-status=pending"
              className={`grow-0 order-[0] text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
                order_status === "pending"
                  ? "bg-[#fda600] text-black"
                  : "bg-[#d9d9d9] text-[#9d9d9d]"
              }`}
            >
              Pending
            </Link>
            <Link
              href="/orders?order-status=ready-to-deliver"
              className={`grow-0 order-[0] text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
                order_status === "ready-to-deliver"
                  ? "bg-[#fda600] text-black"
                  : "bg-[#d9d9d9] text-[#9d9d9d]"
              }`}
            >
              Ready to deliver
            </Link>
            <Link
              href="/orders?order-status=delivered"
              className={`grow-0 order-[0] text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
                order_status === "delivered"
                  ? "bg-[#fda600] text-black"
                  : "bg-[#d9d9d9] text-[#9d9d9d]"
              }`}
            >
              Delivered
            </Link>
            <Link
              href="/orders?order-status=returned"
              className={`grow-0 order-[0] text-[10px] leading-[13.5px] md:text-base py-1.5 px-2.5 md:py-2 md:px-4 rounded-xl md:rounded-[30px] transition-colors duration-100 ease-in-out ${
                order_status === "returned"
                  ? "bg-[#fda600] text-black"
                  : "bg-[#d9d9d9] text-[#9d9d9d]"
              }`}
            >
              Returned
            </Link>
          </nav>
          <div className="p-2.5 bg-white rounded min-h-[450px]">
            <table className="min-w-full divide-y divide-gray-200  table-fixed text-black font-satoshi">
              <thead>
                <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-sm">
                  <th className="py-2 px-1 text-center   ">ID</th>
                  <th className="py-2 px-1 text-center ">Date</th>
                  <th className="py-2 px-1 text-center  ">Customer Name</th>
                  <th className="py-2 px-1 text-center ">Address</th>
                  <th className="py-2 px-1  text-center ">Payment Status</th>
                  <th className="py-2 px-1 text-center ">Order Status</th>
                  <th className="py-2 px-1 text-center">Items</th>
                </tr>
              </thead>
              <tbody className="align-top">{orderItems}</tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OrderTable;
