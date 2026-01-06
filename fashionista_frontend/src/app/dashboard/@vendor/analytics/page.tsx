import React from "react";
import TopBanner from "@/app/components/TopBanner";
import Link from "next/link";
import BarChart from "@/app/components/Charts";
import { ChartOptions, ChartData } from "chart.js";
interface CustomerProp {
  ranking: string;
  name: string;
  city: string;
  area: string;
  total_order: number;
}
const page = () => {
  const data: ChartData<"bar", number[], string> = {
    labels: [
      "Jan",
      "Feb",
      "Mar",
      "April",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sept",
      "Oct",
      "Nov",
      "Dec",
    ],
    datasets: [
      {
        label: "Sales by month",
        data: [2, 5, 8, 10, 24, 12, 18, 20, 25, 15, 26, 31],
        borderWidth: 1,
        backgroundColor: "#fda600",
        barThickness: 15,
        barPercentage: 0.8,
        categoryPercentage: 0.5,
      },
    ],
  };
  const options: ChartOptions<"bar"> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: "top" },
      title: {
        display: true,
        text: "",
      },
    },
    scales: {
      x: {
        stacked: false,
      },
      y: {
        stacked: false,
        ticks: {
          stepSize: 5,
        },
      },
    },
  };
  const customers: CustomerProp[] = [
    {
      ranking: "#001",
      name: "Jennifer Osato",
      city: "Lagos state",
      area: "Surulere",
      total_order: 10,
    },
    {
      ranking: "#002",
      name: "Daniel Iyke",
      city: "Enugu state",
      area: "Ochara layout",
      total_order: 20,
    },
  ];
  const prodList = customers.map((customer) => (
    <tr key={customer.ranking} className="h-[50px] text-[15px] leading-[21px]">
      <td className="py-2 px-2  text-center align-middle">
        {customer.ranking}
      </td>
      <td className="py-6 px-2 text-center align-middle">{customer.name}</td>
      <td className="py-2 px-2 text-center align-middle ">{customer.city}</td>
      <td className="py-2 px-2 text-center align-middle ">{customer.area}</td>
      <td className="py-2 px-2 text-center align-middle ">
        {customer.total_order}
      </td>
    </tr>
  ));
  return (
    <div className="mt-[125px] space-y-6 px-6 pb-10">
      <TopBanner title="Sales Analytics" />
      <div className="flex items-center justify-between flex-wrap font-satoshi ">
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M20.9431 22.5H21.4946C22.7881 22.5 23.817 21.9106 24.7409 21.0865C27.0877 18.9929 21.5709 16.875 19.6875 16.875M17.4375 5.70237C17.693 5.6517 17.9583 5.625 18.2304 5.625C20.2778 5.625 21.9375 7.13604 21.9375 9C21.9375 10.864 20.2778 12.375 18.2304 12.375C17.9583 12.375 17.693 12.3483 17.4375 12.2976"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                />
                <path
                  d="M5.04148 18.1251C3.71513 18.8359 0.237531 20.2872 2.35562 22.1033C3.39029 22.9905 4.54265 23.625 5.99144 23.625H14.2586C15.7074 23.625 16.8597 22.9905 17.8944 22.1033C20.0125 20.2872 16.5349 18.8359 15.2085 18.1251C12.0983 16.4583 8.15174 16.4583 5.04148 18.1251Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
                <path
                  d="M14.625 8.4375C14.625 10.9228 12.6102 12.9375 10.125 12.9375C7.63972 12.9375 5.625 10.9228 5.625 8.4375C5.625 5.95222 7.63972 3.9375 10.125 3.9375C12.6102 3.9375 14.625 5.95222 14.625 8.4375Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Total Customer</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              18
            </p>
            <Link
              href="/"
              className=" text-sm font-bold px-2.5 p-1.5 bg-[#F6F6F6] text-[#5A6465] rounded-[20px]"
            >
              See All &#8594;
            </Link>
          </div>
        </div>
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M4.357 19.1468L3.003 11.0698C2.79827 9.84857 2.69592 9.23796 3.0237 8.83773C3.35149 8.4375 3.95394 8.4375 5.15884 8.4375H21.8412C23.0461 8.4375 23.6485 8.4375 23.9763 8.83773C24.3041 9.23796 24.2017 9.84857 23.997 11.0698L22.643 19.1468C22.1942 21.824 21.9698 23.1625 21.0536 23.9563C20.1375 24.75 18.8167 24.75 16.1755 24.75H10.8245C8.18321 24.75 6.86253 24.75 5.94636 23.9563C5.03018 23.1625 4.80579 21.824 4.357 19.1468Z"
                  fill="white"
                />
                <path
                  d="M19.6875 8.4375C19.6875 5.02023 16.9173 2.25 13.5 2.25C10.0827 2.25 7.3125 5.02023 7.3125 8.4375"
                  stroke="white"
                  stroke-width="2.1875"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Total Revenue</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              $42,500
            </p>
            <Link
              href="/"
              className=" text-sm font-bold px-2.5 p-1.5 bg-[#F6F6F6] text-[#5A6465] rounded-[20px]"
            >
              See All &#8594;
            </Link>
          </div>
        </div>
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M19.125 2.25V4.5M13.5 2.25V4.5M7.875 2.25V4.5"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M3.9375 14.625V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V14.625C23.0625 17.8069 23.0625 19.3979 22.074 20.3865C21.0854 21.375 19.4944 21.375 16.3125 21.375H10.6875C7.50552 21.375 5.91453 21.375 4.92602 20.3865C3.9375 19.3979 3.9375 17.8069 3.9375 14.625Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
                <path
                  d="M3.9375 18V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V18C23.0625 21.1819 23.0625 22.7729 22.074 23.7615C21.0854 24.75 19.4944 24.75 16.3125 24.75H10.6875C7.50552 24.75 5.91453 24.75 4.92602 23.7615C3.9375 22.7729 3.9375 21.1819 3.9375 18Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
                <path
                  d="M9 16.875H13.5M9 11.25H18"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Total Orders</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              91K
            </p>
            <Link
              href="/"
              className=" text-sm font-bold px-2.5 p-1.5 bg-[#F6F6F6] text-[#5A6465] rounded-[20px]"
            >
              See All &#8594;
            </Link>
          </div>
        </div>
      </div>
      <div className="w-full flex items-center justify-between">
        <div className="w-[47%]">
          <BarChart options={options} data={data} />
        </div>
        <div className="w-[47%]">
          <BarChart options={options} data={data} />
        </div>
      </div>
      <div className="p-8 bg-white rounded-[10px]">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 rounded-[5px]">
            <tr>
              <th className="px-6 py-3 font-medium text-black text-center">
                Ranking
              </th>
              <th className="px-6 py-3  font-medium text-black text-center">
                Customer
              </th>
              <th className="px-6 py-3  font-medium text-black text-center">
                City
              </th>
              <th className="px-6 py-3 font-medium text-black text-center">
                Area
              </th>
              <th className="px-6 py-3 font-medium text-black text-center">
                Total Order
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {prodList}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default page;
