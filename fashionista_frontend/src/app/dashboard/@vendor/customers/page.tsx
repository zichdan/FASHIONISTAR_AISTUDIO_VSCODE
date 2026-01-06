import TopBanner from "@/app/components/TopBanner";
import React from "react";

interface CustomerProp {
  name: string;
  date: string;
  address: string;
  status: "customer" | "ex-customer";
  rating: number;
  items: number;
}
const page = () => {
  const customers: CustomerProp[] = [
    {
      name: "Micheal Atafor",
      date: "April 2nd, 2024",
      address: "312 W Festac rd.",
      status: "customer",
      rating: 5,
      items: 10,
    },
    {
      name: "Micheal Atafor",
      date: "April 2nd, 2024",
      address: "312 W Festac rd.",
      status: "ex-customer",
      rating: 5,
      items: 5,
    },
    {
      name: "Micheal Atafor",
      date: "April 2nd, 2024",
      address: "312 W Festac rd.",
      status: "customer",
      rating: 5,
      items: 12,
    },
    {
      name: "Micheal Atafor",
      date: "April 2nd, 2024",
      address: "312 W Festac rd.",
      status: "ex-customer",
      rating: 5,
      items: 1,
    },
  ];

  const customerList = customers.map((customer) => {
    return (
      <tr
        key={customer.name}
        className="h-[50px] text-black text-[15px] leading-[21px]"
      >
        <td className="pl-2 py-6 flex justify-end">
          <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
        </td>
        <td className="py-6 px-2 text-center align-middle">{customer.name}</td>
        <td className="py-6 px-2 text-center align-middle">{customer.date}</td>
        <td className="py-6 px-2 text-center align-middle">
          {customer.address}
        </td>
        <td className="py-6 px-2 text-center align-middle ">
          <div
            className={`${
              customer.status == "customer"
                ? "bg-[#EDFAF3] text-[#25784A] "
                : "bg-[#FDFAE4] text-[#F1D858]"
            } px-3 py-[5px] w-fit text-center mx-auto rounded-[40px] gap-2.5 flex items-center justify-center`}
          >
            <div
              className={`${
                customer.status == "customer" ? "bg-[#25784A]" : "bg-[#F1D858]"
              } w-2.5 h-2.5 rounded-full`}
            />
            {customer.status}
          </div>
        </td>
        <td className="py-6 px-2 text-center align-middle flex items-center justify-center gap-1 ">
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M13.7276 3.44418L15.4874 6.99288C15.7274 7.48687 16.3673 7.9607 16.9073 8.05143L20.0969 8.58575C22.1367 8.92853 22.6167 10.4206 21.1468 11.8925L18.6671 14.3927C18.2471 14.8161 18.0172 15.6327 18.1471 16.2175L18.8571 19.3125C19.417 21.7623 18.1271 22.71 15.9774 21.4296L12.9877 19.6452C12.4478 19.3226 11.5579 19.3226 11.0079 19.6452L8.01827 21.4296C5.8785 22.71 4.57865 21.7522 5.13859 19.3125L5.84851 16.2175C5.97849 15.6327 5.74852 14.8161 5.32856 14.3927L2.84884 11.8925C1.389 10.4206 1.85895 8.92853 3.89872 8.58575L7.08837 8.05143C7.61831 7.9607 8.25824 7.48687 8.49821 6.99288L10.258 3.44418C11.2179 1.51861 12.7777 1.51861 13.7276 3.44418Z"
              fill="#FDA600"
            />
          </svg>

          {customer.rating}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {customer.items}items
        </td>
      </tr>
    );
  });

  return (
    <div className="mt-[125px] px-6 space-y-8">
      <TopBanner title="All Customers" />
      <div className="flex items-center justify-between">
        <div className="py-4 space-y-8">
          <div>
            <h2 className=" font-satoshi font-medium text-xl leading-[27px] text-blaxk">
              Customers (1,688)
            </h2>
            <p className="text-sm leading-[19px] text-[#4E4E4E]">
              Customers that have purchased product from vendor
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button className="px-4 py-2 bg-[#fda600] rounded-[30px] text-black font-medium outline-none ">
              Total customers
            </button>
            <button className="px-4 py-2 bg-[#d9d9d9] rounded-[30px] text-[#4E4E4E] font-medium outline-none">
              Active Now
            </button>
          </div>
        </div>
        <div>
          <button className="py-2.5 px-5 bg-[#fda600] font-medium text-black">
            Add customer
          </button>
        </div>
      </div>
      <div className="p-8 bg-white rounded-[10px] h-[441px]">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 rounded-[5px]">
            <tr>
              <th className="pl-2 py-4 flex justify-end">
                <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
              </th>
              <th className="px-3  py-4 text-lg leading-6 font-medium text-black text-left">
                Customer
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Date
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Address
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Status
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Ratings
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Items
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {customerList}
          </tbody>
        </table>
      </div>
      <div className="w-full h-20 flex items-center justify-between">
        <button className="flex items-center gap-2">
          <svg
            width="18"
            height="19"
            viewBox="0 0 18 19"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M3 9.5H15"
              stroke="black"
              stroke-width="1.2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M6.74997 13.25C6.74997 13.25 3.00001 10.4882 3 9.5C2.99999 8.5118 6.75 5.75 6.75 5.75"
              stroke="black"
              stroke-width="1.2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
          Previuos
        </button>
        <span>Page 1 of 120</span>
        <button className="flex items-center gap-2">
          Next{" "}
          <svg
            width="18"
            height="19"
            viewBox="0 0 18 19"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M15 9.5L3 9.5"
              stroke="black"
              stroke-width="1.2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M11.25 5.75C11.25 5.75 15 8.5118 15 9.5C15 10.4882 11.25 13.25 11.25 13.25"
              stroke="black"
              stroke-width="1.2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </button>
      </div>
    </div>
  );
};

export default page;
