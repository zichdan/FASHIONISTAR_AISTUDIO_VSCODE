import React from "react";
import TopBanner from "@/app/components/TopBanner";
import Link from "next/link";
import BarChart from "@/app/components/Charts";
import { ChartOptions, ChartData } from "chart.js";
interface PaymentProp {
  invoice_number: string;
  customer: string;
  date: string;
  status: "pending" | "paid" | "failed";
  amount: number;
}
const pages = () => {
  const payment_history: PaymentProp[] = [
    {
      invoice_number: "50899065",
      customer: "Bank transfer",
      date: "12.05.24 09.00.09",
      status: "paid",
      amount: 10059,
    },
    {
      invoice_number: "34299009",
      date: "05.07.24 09.00.09",
      customer: "Bank transfer",

      status: "paid",
      amount: 10059,
    },
    {
      invoice_number: "34299229",
      date: "30.06.24 12.046.09",
      customer: "Bank transfer",

      status: "pending",
      amount: 10059,
    },
    {
      invoice_number: "34299339",
      date: "12.05.24 09.00.09",
      customer: "Bank transfer",

      status: "paid",
      amount: 10059,
    },
  ];
  const withdrawalList = payment_history.map((withdrawal) => {
    return (
      <tr
        key={withdrawal.invoice_number}
        className="h-[50px] text-black text-[15px] leading-[21px]"
      >
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.invoice_number}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.customer}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.date}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.amount}
        </td>
        <td className="py-6 px-2 text-center align-middle ">
          <div
            className={`${
              withdrawal.status == "paid"
                ? "bg-[#EDFAF3] text-[#25784A] "
                : "bg-[#FEE8E7] text-[#EA1705]"
            } px-2 py-[5px] rounded-[40px] gap-2.5 flex items-center justify-center text-xs`}
          >
            <div
              className={`${
                withdrawal.status == "paid" ? "bg-[#25784A]" : "bg-[#EA1705]"
              } w-2.5 h-2.5 rounded-full`}
            />
            {withdrawal.status}
          </div>
        </td>
        <td>
          <button>
            <svg
              width="20"
              height="20"
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M16.25 4.58301L15.7336 12.9373C15.6016 15.0717 15.5357 16.1389 15.0007 16.9063C14.7361 17.2856 14.3956 17.6058 14.0006 17.8463C13.2017 18.333 12.1325 18.333 9.99392 18.333C7.8526 18.333 6.78192 18.333 5.98254 17.8454C5.58733 17.6044 5.24667 17.2837 4.98223 16.9037C4.4474 16.1352 4.38287 15.0664 4.25384 12.929L3.75 4.58301"
                stroke="black"
                stroke-linecap="round"
              />
              <path
                d="M2.5 4.58366H17.5M13.3797 4.58366L12.8109 3.4101C12.433 2.63054 12.244 2.24076 11.9181 1.99767C11.8458 1.94374 11.7693 1.89578 11.6892 1.85424C11.3283 1.66699 10.8951 1.66699 10.0287 1.66699C9.14067 1.66699 8.69667 1.66699 8.32973 1.86209C8.24842 1.90533 8.17082 1.95524 8.09774 2.0113C7.76803 2.26424 7.58386 2.66828 7.21551 3.47638L6.71077 4.58366"
                stroke="black"
                stroke-linecap="round"
              />
              <path
                d="M7.91699 13.75V8.75"
                stroke="black"
                stroke-linecap="round"
              />
              <path
                d="M12.083 13.75V8.75"
                stroke="black"
                stroke-linecap="round"
              />
            </svg>
          </button>
        </td>
      </tr>
    );
  });
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
        label: "Awaiting payment",
        data: [2, 5, 8, 10, 24, 12, 18, 20, 25, 15, 26, 31],
        borderWidth: 1,
        backgroundColor: "#fda600",
        barThickness: 15,
        barPercentage: 0.8,
        categoryPercentage: 0.5,
      },
      {
        label: "Paid",
        data: [6, 12, 8, 15, 17, 9, 13, 8, 12, 25, 16, 22],
        borderWidth: 1,
        backgroundColor: "#000",
        barThickness: 15,
        barPercentage: 0.8,
        categoryPercentage: 0.5,
      },
    ],
  };
  const options: ChartOptions<"bar"> = {
    maintainAspectRatio: false,
    responsive: true,
    plugins: {
      legend: { position: "top" },
      title: {
        display: true,
        text: "Sales of the month",
      },
    },
    scales: {
      x: {
        stacked: false,
      },
      y: {
        stacked: false,
      },
    },
  };
  return (
    <div className="mt-[125px] space-y-10 px-6 pb-10">
      <TopBanner title="Payments" />
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
                  d="M16.875 8.4375C16.875 8.4375 17.4375 8.4375 18 9.5625C18 9.5625 19.7867 6.75 21.375 6.1875"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M24.75 7.875C24.75 10.9816 22.2316 13.5 19.125 13.5C16.0184 13.5 13.5 10.9816 13.5 7.875C13.5 4.7684 16.0184 2.25 19.125 2.25C22.2316 2.25 24.75 4.7684 24.75 7.875Z"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                />
                <path
                  d="M25.5937 14.8997C25.593 14.4336 25.2145 14.0565 24.7485 14.0574C24.2826 14.0582 23.9055 14.4366 23.9062 14.9026L25.5937 14.8997ZM10.199 7.59667C10.665 7.59403 11.0406 7.21414 11.038 6.74816C11.0354 6.28218 10.6555 5.90656 10.1895 5.90919L10.199 7.59667ZM15.1875 23.9063H11.8125V25.5938H15.1875V23.9063ZM11.8125 23.9063C9.6785 23.9063 8.14897 23.9051 6.97382 23.7723C5.81418 23.6413 5.11154 23.3919 4.58133 22.9731L3.53546 24.2975C4.41675 24.9935 5.47697 25.3014 6.7844 25.4492C8.07633 25.5951 9.71811 25.5938 11.8125 25.5938V23.9063ZM1.40625 15.7501C1.40625 17.7176 1.40464 19.2732 1.56107 20.5001C1.72049 21.75 2.05516 22.769 2.8046 23.6096L4.0642 22.4866C3.62924 21.9987 3.37172 21.3584 3.23503 20.2865C3.09536 19.1913 3.09375 17.7623 3.09375 15.7501H1.40625ZM4.58133 22.9731C4.39363 22.825 4.22066 22.6621 4.0642 22.4866L2.8046 23.6096C3.02702 23.8591 3.27162 24.0891 3.53546 24.2975L4.58133 22.9731ZM23.9062 15.7501C23.9062 17.7623 23.9047 19.1913 23.7649 20.2865C23.6283 21.3584 23.3707 21.9987 22.9358 22.4866L24.1954 23.6096C24.9448 22.769 25.2795 21.75 25.4389 20.5001C25.5953 19.2732 25.5937 17.7176 25.5937 15.7501H23.9062ZM15.1875 25.5938C17.2819 25.5938 18.9236 25.5951 20.2156 25.4492C21.523 25.3014 22.5832 24.9935 23.4646 24.2975L22.4187 22.9731C21.8884 23.3919 21.1858 23.6413 20.0261 23.7723C18.8511 23.9051 17.3215 23.9063 15.1875 23.9063V25.5938ZM22.9358 22.4866C22.7793 22.6621 22.6064 22.825 22.4187 22.9731L23.4646 24.2975C23.7284 24.0891 23.973 23.8591 24.1954 23.6096L22.9358 22.4866ZM3.09375 15.7501C3.09375 13.7379 3.09536 12.3088 3.23503 11.2136C3.37172 10.1417 3.62924 9.50145 4.0642 9.01358L2.8046 7.89061C2.05516 8.73122 1.72049 9.75011 1.56107 11.0002C1.40464 12.2269 1.40625 13.7826 1.40625 15.7501H3.09375ZM3.53546 7.20265C3.27162 7.41101 3.02702 7.64114 2.8046 7.89061L4.0642 9.01358C4.22066 8.83808 4.39363 8.6752 4.58133 8.52698L3.53546 7.20265ZM25.5937 15.7501C25.5937 15.4585 25.5942 15.1731 25.5937 14.8997L23.9062 14.9026C23.9067 15.1742 23.9062 15.4544 23.9062 15.7501H25.5937ZM10.1895 5.90919C8.606 5.91816 7.31712 5.95463 6.26128 6.12126C5.18964 6.29039 4.29595 6.60206 3.53546 7.20265L4.58133 8.52698C5.03951 8.16513 5.62639 7.92984 6.52435 7.78813C7.43809 7.64392 8.60781 7.60567 10.199 7.59667L10.1895 5.90919Z"
                  fill="white"
                />
                <path
                  d="M11.25 20.25H12.9375"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M16.3125 20.25H20.25"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M2.8125 12.375H11.25"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Payments</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              20
            </p>
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
            <p className="font-satoshi text-xl text-black">Total Payments</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              $432.92
            </p>
          </div>
        </div>
      </div>
      <div className="flex justify-end mx-auto w-full">
        <BarChart options={options} data={data} />
      </div>
      <div className="shadow-card_shadow rounded-[10px] bg-[#fff] p-[30px] min-h-[200px] space-y-4">
        <h2 className="font-satoshi font-medium text-xltext-black">
          All Payment Invoice
        </h2>

        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 rounded-[5px]">
            <tr>
              <th className="px-6  py-4 text-lg leading-6 font-medium text-black text-center">
                Invoice Number
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Customer
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Date
              </th>

              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Amount
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                Status
              </th>
              <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center"></th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {withdrawalList}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default pages;
