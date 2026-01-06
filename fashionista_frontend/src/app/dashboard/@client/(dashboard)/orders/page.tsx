import React from "react";
// import { getClientOrders } from "@/app/actions/client";
const page = async () => {
  const order_history = [
    {
      items: "5",
      order: "Agbada",
      date: "12.05.24",
      status: "processing",
      total_amount: 10059,
    },
    {
      items: "2",
      order: "Isi agu native wear",
      date: "12.05.24",
      status: "Completed",
      total_amount: 12059,
    },
    {
      items: "5",
      order: "Agbada",
      date: "12.05.24",
      status: "processing",
      total_amount: 14000,
    },
    {
      items: "5",
      order: "Agbada",
      date: "12.05.24",
      status: "completed",
      total_amount: 12500,
    },
  ];
  // const orders = await getClientOrders();
  const orderList = order_history.map((order, index) => {
    return (
      <tr
        key={index}
        className="h-[50px] text-black text-[15px] leading-[21px]"
      >
        <td className="py-6 px-2 text-center align-middle">{order.date}</td>
        <td className="py-6 px-2 text-center align-middle">{order.order}</td>
        <td className="py-6 px-2 text-center align-middle">{order.status}</td>
        <td className="py-6 px-2 text-center align-middle">
          {order.total_amount}
        </td>
        <td className="py-6 px-2 text-center align-middle ">
          {order.items}items
        </td>
      </tr>
    );
  });
  return (
    <div className="space-y-10">
      <div>
        <h3 className="font-satoshi font-medium text-3xl text-black">Orders</h3>
        <p className="font-satoshi text-xl text-black">
          This section displays both previous and recent orders.
        </p>
      </div>
      <div className="shadow-card_shadow rounded-[10px] bg-[#fff] p-[30px] min-h-[200px] space-y-4">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 rounded-[5px]">
            <tr>
              <th className="px-6  py-4 text-lg leading-6 font-medium text-black text-center">
                Date
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Order
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Status
              </th>

              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Total Amount
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Items
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center"></th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {orderList}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default page;
