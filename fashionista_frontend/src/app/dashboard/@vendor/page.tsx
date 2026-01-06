import Link from "next/link";
import React from "react";
import TopBanner from "@/app/components/TopBanner";
import BarChart from "@/app/components/Charts";
import { ChartOptions, ChartData } from "chart.js";
import { fetchWithAuth } from "../../utils/fetchAuth";
import { getVendor } from "@/app/utils/libs";

const page = async () => {
  const getVendorStats = async () => {
    try {
      const vendorStat = await fetchWithAuth("/vendor/dashboard");
      return vendorStat;
    } catch (error) {
      console.log(error);
    }
  };
  // const vendorStat = await getVendorStats();
  // console.log(vendorStat);
  const vendor = await getVendor();
  console.log(vendor);

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
    maintainAspectRatio: false,
    responsive: true,
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
  return (
    <div className="flex flex-col gap-10 mt-[125px] px-5 md:px-10 pb-10">
      <TopBanner title="Dashboard" />

      <div className="">
        <h2 className="font-bon_foyage text-5xl leading-[48px] text-black py-6">
          Overview
        </h2>
        <div className="flex flex-wrap gap-4">
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex flex-col justify-between">
            <div className="flex items-center gap-4">
              <svg
                width="45"
                height="45"
                viewBox="0 0 45 45"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <circle cx="22.5" cy="22.5" r="22.5" fill="#B1F4FF" />
                <path
                  d="M31.5 19.125C30.6054 14.6414 26.4519 11.25 21.4642 11.25C15.8237 11.25 11.25 15.5871 11.25 20.9363C11.25 23.5064 12.3055 25.8417 14.0271 27.5747C14.4062 27.9563 14.6593 28.4776 14.5571 29.0141C14.3885 29.8914 14.0065 30.7097 13.4472 31.3917C14.9189 31.663 16.4492 31.4187 17.7615 30.7268C18.2254 30.4823 18.4574 30.36 18.6211 30.3352C18.7357 30.3179 18.8849 30.3341 19.125 30.3752"
                  stroke="#13849E"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M21.375 27.2944C21.375 30.5633 24.1456 33.2138 27.5625 33.2138C27.9642 33.2143 28.3648 33.1771 28.7595 33.1031C29.0436 33.0497 29.1856 33.023 29.2848 33.0382C29.3839 33.0533 29.5245 33.1281 29.8055 33.2775C30.6004 33.7003 31.5275 33.8496 32.419 33.6837C32.0802 33.267 31.8488 32.767 31.7466 32.2308C31.6847 31.903 31.8381 31.5844 32.0677 31.3512C33.1107 30.2921 33.75 28.865 33.75 27.2944C33.75 24.0255 30.9794 21.375 27.5625 21.375C24.1456 21.375 21.375 24.0255 21.375 27.2944Z"
                  fill="#13849E"
                />
              </svg>
              <span className="font-satoshi text-xl text-black">Chats</span>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-satoshi space-x-2">
                <span className="font-medium text-[40px] leading-[54px] text-[#000]">
                  8
                </span>
                <span className="text-[#858585]">New Chats</span>
              </p>
              <Link
                href="/"
                className="py-1.5 px-2.5 bg-[#f6f6f6] rounded-[20px] font-bold font-satoshi text-sm text-[#5A6465]"
              >
                See all &#8594;
              </Link>
            </div>
          </div>
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex flex-col justify-between">
            <div className="flex items-center gap-4">
              <div className="flex justify-center items-center w-[45px] h-[45px] bg-[#FEF3D3] rounded-full">
                <svg
                  width="27"
                  height="27"
                  viewBox="0 0 27 27"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M15.4435 3.8747L17.4233 7.86699C17.6933 8.42273 18.4132 8.95578 19.0207 9.05786L22.609 9.65897C24.9038 10.0446 25.4438 11.7232 23.7901 13.3791L21.0005 16.1918C20.528 16.6681 20.2694 17.5868 20.4155 18.2447L21.2142 21.7266C21.8441 24.4826 20.393 25.5487 17.9746 24.1083L14.6112 22.1008C14.0038 21.7379 13.0026 21.7379 12.3839 22.1008L9.02055 24.1083C6.61331 25.5487 5.15098 24.4712 5.78091 21.7266L6.57957 18.2447C6.7258 17.5868 6.46708 16.6681 5.99463 16.1918L3.20494 13.3791C1.56262 11.7232 2.09132 10.0446 4.38606 9.65897L7.97442 9.05786C8.5706 8.95578 9.29052 8.42273 9.56049 7.86699L11.5402 3.8747C12.6201 1.70843 14.3749 1.70843 15.4435 3.8747Z"
                    fill="#ECB219"
                  />
                </svg>
              </div>

              <span className="font-satoshi text-xl text-black">
                Store Review
              </span>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-satoshi space-x-2 ">
                <span className="font-medium text-[40px] leading-[54px] text-[#000]">
                  4.5
                </span>
                <span className="text-[#858585]">1200 Reviews</span>
              </p>
              <Link
                href="/"
                className="py-1.5 px-2.5 bg-[#f6f6f6] rounded-[20px] font-bold font-satoshi text-sm text-[#5A6465]"
              >
                See all &#8594;
              </Link>
            </div>
          </div>
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex justify-evenly items-center">
            <div className="w-[70px] h-[70px] bg-[#fda600] rounded-full flex justify-center items-center">
              <svg
                width="35"
                height="35"
                viewBox="0 0 35 35"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M24.7918 2.91699V5.83366M17.5002 2.91699V5.83366M10.2085 2.91699V5.83366"
                  stroke="white"
                  strokeWidth="1.43431"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M5.10449 18.9583V13.125C5.10449 9.00021 5.10449 6.93782 6.3859 5.65641C7.66731 4.375 9.7297 4.375 13.8545 4.375H21.1462C25.2709 4.375 27.3333 4.375 28.6147 5.65641C29.8962 6.93782 29.8962 9.00021 29.8962 13.125V18.9583C29.8962 23.0831 29.8962 25.1455 28.6147 26.4269C27.3333 27.7083 25.2709 27.7083 21.1462 27.7083H13.8545C9.7297 27.7083 7.66731 27.7083 6.3859 26.4269C5.10449 25.1455 5.10449 23.0831 5.10449 18.9583Z"
                  stroke="white"
                  strokeWidth="1.43431"
                />
                <path
                  d="M5.10449 23.3333V13.125C5.10449 9.00021 5.10449 6.93782 6.3859 5.65641C7.66731 4.375 9.7297 4.375 13.8545 4.375H21.1462C25.2709 4.375 27.3333 4.375 28.6147 5.65641C29.8962 6.93782 29.8962 9.00021 29.8962 13.125V23.3333C29.8962 27.4581 29.8962 29.5205 28.6147 30.8019C27.3333 32.0833 25.2709 32.0833 21.1462 32.0833H13.8545C9.7297 32.0833 7.66731 32.0833 6.3859 30.8019C5.10449 29.5205 5.10449 27.4581 5.10449 23.3333Z"
                  stroke="white"
                  strokeWidth="1.43431"
                />
                <path
                  d="M11.667 21.8747H17.5003M11.667 14.583H23.3337"
                  stroke="white"
                  strokeWidth="1.43431"
                  strokeLinecap="round"
                />
              </svg>
            </div>

            <div className="flex flex-col font-satoshi">
              <h2 className="font-satoshi text-xl text-black">
                {" "}
                Average order value
              </h2>
              <span className="font-medium text-[40px] leading-[54px] text-black">
                {" "}
                $450
              </span>
            </div>
          </div>
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex flex-col justify-between">
            <div className="flex items-center gap-4">
              <div className="flex justify-center items-center w-[45px] h-[45px] bg-[#F9D9DA] rounded-full">
                <svg
                  width="27"
                  height="27"
                  viewBox="0 0 27 27"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M4.357 19.1468L3.003 11.0698C2.79827 9.84857 2.69592 9.23796 3.0237 8.83773C3.35149 8.4375 3.95394 8.4375 5.15884 8.4375H21.8412C23.0461 8.4375 23.6485 8.4375 23.9763 8.83773C24.3041 9.23796 24.2017 9.84857 23.997 11.0698L22.643 19.1468C22.1942 21.824 21.9698 23.1625 21.0536 23.9563C20.1375 24.75 18.8167 24.75 16.1755 24.75H10.8245C8.18321 24.75 6.86253 24.75 5.94636 23.9563C5.03018 23.1625 4.80579 21.824 4.357 19.1468Z"
                    fill="#E17575"
                  />
                  <path
                    d="M19.6875 8.4375C19.6875 5.02023 16.9173 2.25 13.5 2.25C10.0827 2.25 7.3125 5.02023 7.3125 8.4375"
                    stroke="#E17575"
                    strokeWidth="2.1875"
                  />
                </svg>
              </div>

              <span className="font-satoshi text-xl text-black">
                Out of stock
              </span>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-satoshi space-x-2 ">
                <span className="font-medium text-[40px] leading-[54px] text-[#000]">
                  4
                </span>
                <span className="text-[#858585]">Products</span>
              </p>
              <Link
                href="/"
                className="py-1.5 px-2.5 bg-[#f6f6f6] rounded-[20px] font-bold font-satoshi text-sm text-[#5A6465]"
              >
                See all &#8594;
              </Link>
            </div>
          </div>
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex flex-col justify-between">
            <div className="flex items-center gap-4">
              <div className="flex justify-center items-center w-[45px] h-[45px] bg-[#C5FECB] rounded-full">
                <svg
                  width="27"
                  height="27"
                  viewBox="0 0 27 27"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M19.125 2.25V4.5M13.5 2.25V4.5M7.875 2.25V4.5"
                    stroke="#20AB2C"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M3.9375 14.625V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V14.625C23.0625 17.8069 23.0625 19.3979 22.074 20.3865C21.0854 21.375 19.4944 21.375 16.3125 21.375H10.6875C7.50552 21.375 5.91453 21.375 4.92602 20.3865C3.9375 19.3979 3.9375 17.8069 3.9375 14.625Z"
                    stroke="#20AB2C"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M3.9375 18V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V18C23.0625 21.1819 23.0625 22.7729 22.074 23.7615C21.0854 24.75 19.4944 24.75 16.3125 24.75H10.6875C7.50552 24.75 5.91453 24.75 4.92602 23.7615C3.9375 22.7729 3.9375 21.1819 3.9375 18Z"
                    stroke="#20AB2C"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M9 16.875H13.5M9 11.25H18"
                    stroke="#20AB2C"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                </svg>
              </div>

              <span className="font-satoshi text-xl text-black">Orders</span>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-satoshi space-x-2 ">
                <span className="font-medium text-[40px] leading-[54px] text-[#000]">
                  12
                </span>
                <span className="text-[#858585]">Unfulfilled</span>
              </p>
              <Link
                href="/"
                className="py-1.5 px-2.5 bg-[#f6f6f6] rounded-[20px] font-bold font-satoshi text-sm text-[#5A6465]"
              >
                See all &#8594;
              </Link>
            </div>
          </div>
          <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex justify-evenly items-center">
            <div className="w-[70px] h-[70px] bg-[#fda600] rounded-full flex justify-center items-center">
              <svg
                width="35"
                height="35"
                viewBox="0 0 35 35"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M30.625 30.625H14.5833C9.77108 30.625 7.36495 30.625 5.86998 29.1301C4.375 27.635 4.375 25.2289 4.375 20.4167V4.375"
                  stroke="white"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                />
                <path
                  d="M11.6611 24.7907C16.8113 24.7907 27.579 22.6554 27.2665 9.38146M24.0446 11.7299L26.7914 8.96354C27.0736 8.67939 27.5318 8.67726 27.8166 8.95879L30.6195 11.7299"
                  stroke="white"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>

            <div className="flex flex-col font-satoshi">
              <h2 className="font-satoshi text-xl text-black"> Sales Total</h2>
              <span className="font-medium text-[40px] leading-[54px] text-black">
                {" "}
                $1,620
              </span>
            </div>
          </div>
        </div>
      </div>
      {/* Charts */}
      <div className="w-full flex items-center justify-between">
        <div className="w-[47%]">
          <BarChart options={options} data={data} />
        </div>
        <div className="w-[47%]">
          <BarChart options={options} data={data} />
        </div>
      </div>
    </div>
  );
};

export default page;
