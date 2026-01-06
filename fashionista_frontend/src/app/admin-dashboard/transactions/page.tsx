import React from "react";

const page = () => {
  const transaction = [
    {
      id: "#456667",
      amount: "$234.99",
      method: "Master card",
      date: "06.06.24, 04:31pm",
    },
    {
      id: "#256660",
      amount: "$234.99",
      method: "Paypal",
      date: "06.06.24, 04:31pm",
    },
    {
      id: "#356667",
      amount: "$234.99",
      method: "Master card",
      date: "06.06.24, 04:31pm",
    },
    {
      id: "##656653",
      amount: "$234.99",
      method: "Paystack",
      date: "06.06.24, 04:31pm",
    },
    {
      id: "##456699",
      amount: "$234.99",
      method: "Paypal",
      date: "06.06.24, 04:31pm",
    },
  ];

  const transactionList = transaction.map((item) => {
    return (
      <tr key={item.id}>
        <td className="font-satoshi font-medium text-black py-5 text-center">
          {item.id}
        </td>
        <td className="font-satoshi font-medium text-black py-5 text-center">
          {item.amount}
        </td>
        <td className="font-satoshi font-medium text-black py-5 text-center">
          {item.method}
        </td>
        <td className="font-satoshi font-medium text-black py-5 text-center">
          {item.date}
        </td>
        <td className="font-satoshi font-medium text-black py-5 text-center">
          <button className="bg-[#fda600] px-5 py-2.5 font-medium text-black">
            Details
          </button>
        </td>
      </tr>
    );
  });
  return (
    <div className="space-y-10 bg-inherit">
      <h3 className="font-satoshi font-medium text-3xl text-black">
        Transactions
      </h3>
      <div className="w-full bg-white rounded-[20px] min-h-[400px] px-3 py-4 md:p-[30px] space-y-5">
        <div className="flex items-center justify-end gap-3">
          <div className="p-2.5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="show 20"
            >
              <option disabled className="">
                show 20
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
          <div className="p-2.5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="status all"
            >
              <option disabled className="">
                status all
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
        </div>
        <table className="min-w-full divide-y divide-gray-200 table-fixed text-black font-satoshi">
          <thead>
            <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-[5px]">
              {/* <th className="pl-2 py-4 flex justify-end">
                <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
              </th> */}
              <th className="p-4 text-center">Transaction ID</th>
              <th className="p-4 text-center">Amount</th>
              <th className="p-4 text-center">Method</th>
              <th className="p-4 text-center">Date</th>
              <th className="p-4 text-center">Action</th>
              {/* <th className="py-3 px-1 text-center">Order Status</th>
              <th className="py-3 px-1 text-center">Items</th> */}
            </tr>
          </thead>
          <tbody className="align-top">{transactionList}</tbody>
        </table>
      </div>
    </div>
  );
};

export default page;
