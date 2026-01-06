import React from "react";
import BarChart from "../components/Charts";
import { ChartOptions, ChartData } from "chart.js";
import Image from "next/image";
import { Suspense } from "react";

import OrderList from "../components/OrderList";
import { OrderProp } from "@/types";

interface MembersProp {
  image: string;
  name: string;
  address: string;
}
interface ActivitiesProp {
  date: string;
  activity: string;
}
interface MarketingProp {
  platform: "facebook" | "instagram" | "twitter" | "google" | "tiktok";
  value: number;
}
const orders: OrderProp[] = [
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
    payment_status: "pending",
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
        label: "Sales",
        data: [2, 5, 8, 10, 24, 12, 18, 20, 25, 15, 26, 31],
        borderWidth: 1,
        backgroundColor: "#fda600",
        barThickness: 15,
        barPercentage: 0.8,
        categoryPercentage: 0.5,
      },
      {
        label: "Visitors",
        data: [6, 12, 8, 15, 17, 9, 13, 8, 12, 25, 16, 22],
        borderWidth: 1,
        backgroundColor: "#000",
        barThickness: 15,
        barPercentage: 0.8,
        categoryPercentage: 0.5,
      },
      {
        label: "Products",
        data: [22, 16, 23, 15, 10, 17, 19, 12, 5, 14, 10, 11],
        borderWidth: 1,
        backgroundColor: "#25784A",
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
  const members: MembersProp[] = [
    {
      name: "Chidera Igwe",
      image: "/woman2.svg",
      address: "Onitsha, Anambra State",
    },
    {
      name: "Chidera Igwe",
      image: "/woman3.svg",
      address: "Onitsha, Anambra State",
    },
    {
      name: "Chidera Igwe",
      image: "/woman4.svg",
      address: "Onitsha, Anambra State",
    },
    {
      name: "Chidera Igwe",
      image: "/man4_asset.svg",
      address: "Onitsha, Anambra State",
    },
  ];
  const membersList = members.map((member, index) => {
    return (
      <div key={index} className="flex justify-between items-center w-full">
        <div className="flex items-center gap-2">
          <div className="w-[45px] h-[45px] rounded-full">
            <Image
              src={member.image}
              alt={member.name}
              width={100}
              height={100}
              className="w-full h-full rounded-full object-cover"
            />
          </div>
          <div>
            <h2 className="font-medium text-[13px] leading-[17.55px] font-satoshi text-black">
              {member.name}
            </h2>
            <p className="font-satoshi text-[10px] leading-[13.5px] text-[#858585] font-medium">
              {member.address}
            </p>
          </div>
        </div>
        <div>
          <button className="py-1.5 px-5 bg-[#fda600] font-satoshi font-medium text-[10px] leading-[14px] text-white">
            Add
          </button>
        </div>
      </div>
    );
  });
  const activities: ActivitiesProp[] = [
    {
      date: "04 Apr, 2024",
      activity:
        "Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed consectetur nec arcu laoreet ipsum",
    },
    {
      date: "23 May, 2024",
      activity:
        "Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed consectetur nec arcu laoreet ipsum",
    },
    {
      date: "12 June, 2024",
      activity:
        "Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed consectetur nec arcu laoreet ipsum",
    },
    {
      date: "30 June, 2024",
      activity:
        "Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed consectetur nec arcu laoreet ipsum",
    },
  ];
  const activitiesList = activities.map((activity, index) => {
    return (
      <div key={index} className="flex items-center gap-4">
        <p className="font-satoshi font-normal text-sm text-black min-w-[87px]">
          {activity.date}
        </p>
        <div className="font-satoshi flex items-center gap-3 ">
          <span className="text-[#fda600] font-medium"> &#8594;</span>
          <span className="text-[10px] leading-[14px] text-[#282828] max-w-[160px]">
            {activity.activity}
          </span>
        </div>
      </div>
    );
  });
  const marketing: MarketingProp[] = [
    {
      platform: "instagram",
      value: 40,
    },
    {
      platform: "tiktok",
      value: 50,
    },
    {
      platform: "twitter",
      value: 10,
    },
    {
      platform: "google",
      value: 90,
    },
    {
      platform: "facebook",
      value: 80,
    },
  ];
  const marketingList = marketing.map((item, index) => {
    return (
      <div key={index} className="flex flex-col gap-1 ">
        <label
          htmlFor="progress-bar"
          className="font-satoshi font-medium text-xs text-[#282828] capitalize"
        >
          {item.platform}
        </label>
        <progress id="progress-bar" value={item.value} max={100} />
      </div>
    );
  });
  return (
    <div className="space-y-10">
      <div>
        <h2 className="font-satoshi font-medium text-3xl text-black">
          Dashboard
        </h2>

        <p className="font-satoshi text-xl text-black">
          Whole data about your business here.
        </p>
      </div>
      <div className="flex flex-wrap gap-4">
        <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex gap-2">
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

          <div className="flex flex-col  gap-2">
            <span className="font-satoshi text-xl text-black">Revenue</span>
            <span className="font-medium text-[40px] leading-[54px] text-[#000]">
              $120.00
            </span>
            <span className="text-[#858585]">
              Shipping fees are not included
            </span>
          </div>
        </div>
        <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex gap-2">
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

          <div className="flex flex-col  gap-2">
            <span className="font-satoshi text-xl text-black">Orders</span>
            <span className="font-medium text-[40px] leading-[54px] text-[#000]">
              420,000
            </span>
            <span className="text-[#858585]">excluding orders in transit</span>
          </div>
        </div>
        <div className="w-full md:w-[48%] lg:w-[32%] h-[170px] bg-[#fff] rounded-[10px] shadow p-5 flex gap-2">
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

          <div className="flex flex-col  gap-2">
            <span className="font-satoshi text-xl text-black">Products</span>
            <span className="font-medium text-[40px] leading-[54px] text-[#000]">
              54
            </span>
            <span className="text-[#858585]">in 19 categories</span>
          </div>
        </div>
      </div>
      {/* Charts */}
      <div>
        <BarChart options={options} data={data} />
      </div>
      <div className="flex items-center flex-wrap justify-between">
        <div className="md:w-[32%] w-full h-[383px] flex flex-col justify-evenly px-4 py-2 bg-white rounded-[10px] shadow-card_shadow">
          <h3 className="text-xl font-medium font-satoshi text-black">
            New Members
          </h3>
          {membersList}
        </div>
        <div className="md:w-[32%] w-full h-[383px] flex flex-col justify-evenly px-5 py-2 bg-white rounded-[10px] shadow-card_shadow">
          <h3 className="text-xl font-medium font-satoshi text-black">
            Recent Activities
          </h3>
          {activitiesList}
        </div>
        <div className="md:w-[32%] w-full h-[383px] flex flex-col justify-evenly px-5 py-2 bg-white rounded-[10px] shadow-card_shadow">
          <h3 className="text-xl font-medium font-satoshi text-black">
            Marketing Channel
          </h3>
          {marketingList}
        </div>
      </div>
      <div className="space-y-8">
        <h2 className="font-satoshi font-medium text-2xl text-black">
          Latest Orders
        </h2>
        <Suspense fallback={<div>Loading ...</div>}>
          <OrderList orders={orders} />
        </Suspense>
      </div>
    </div>
  );
};

export default page;
