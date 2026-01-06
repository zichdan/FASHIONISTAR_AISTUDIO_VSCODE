import React from "react";
import { trackOrder } from "@/app/actions/client";

const page = () => {
  return (
    <div className="space-y-20">
      <div>
        <h3 className="font-satoshi font-medium text-3xl leading-10 text-black">
          Track your Orders
        </h3>
        <p className="font-satoshi text-xl text-black pr-10">
          To track your orders, please enter your order ID in the box below and
          click the “Track” button. This was given to you in your receipt and in
          the confirmation mail you should have received.
        </p>
      </div>
      <form
        action={trackOrder}
        className="flex items-center justify-between flex-wrap"
      >
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="order_id" className="text-xl text-black">
            Order ID
          </label>
          <input
            type="text"
            name="order_id"
            id="order_id"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="email" className="text-xl text-black">
            Billing Email
          </label>
          <input
            type="email"
            name="billing_email"
            id="email"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="w-full flex justify-end py-8">
          <button className="py-[15px] px-12 bg-[#fda600] font-medium text-black outline-none">
            Track
          </button>
        </div>
      </form>
    </div>
  );
};

export default page;
