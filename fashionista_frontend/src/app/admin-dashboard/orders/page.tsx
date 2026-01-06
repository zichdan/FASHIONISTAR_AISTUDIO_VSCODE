import OrderList from "@/app/components/OrderList";
import { OrderProp } from "@/types";
import React from "react";
import Link from "next/link";

const page = () => {
  const order: OrderProp[] = [
    {
      id: 1,
      date: "April 2, 2024",
      customer_name: "Adam Smith",
      address: "some where on earth",
      payment_status: "pending",
      order_status: "pending",
      items: 4,
    },
    {
      id: 2,
      date: "April 2, 2024",
      customer_name: "Adam Smith",
      address: "some where on earth",
      payment_status: "pending",
      order_status: "pending",
      items: 4,
    },
  ];

  const orderItems = order.map((item) => (
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
    <div className="bg-inherit space-y-10">
      <h2 className="font-satoshi font-medium text-3xl leading-10 text-black">
        Orders
      </h2>
      <div
        className={` flex items-center  w-[33%] h-[60px] border-[#d9d9d9] border-[1.5px] bg-white rounded-[5px] px-4 gap-6`}
      >
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
          placeholder="Search"
          className="w-full h-full bg-inherit outline-none focus:outline-none peer"
        />
      </div>
      <div className="p-2.5 bg-white shadow-card_shadow rounded min-h-[200px] py-5">
        <div className="flex items-center justify-end py-5 gap-3">
          <div className="py-2.5 px-5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="status"
            >
              <option disabled className="">
                status
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
          <div className="py-2.5 px-5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select defaultValue="Show 4" className="bg-inherit">
              <option>Show 4</option>
              <option>1</option>
            </select>
          </div>
        </div>
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

export default page;
