"use client";
import React from "react";
import Link from "next/link";
import MultiStep from "@/app/components/MultiStep";

const page = () => {
  return (
    <div className="space-y-5 md:space-y-10 relative">
      <div className="hidden fixed top-14 md:top-0 right-0 w-full md:w-[75%] h-20 md:h-[16%] md:flex justify-between items-center bg-white px-6">
        <div className="flex items-center gap-2 ">
          <Link href="/dashboard/products">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M4 12H20"
                stroke="black"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M8.99996 17C8.99996 17 4.00001 13.3176 4 12C3.99999 10.6824 9 7 9 7"
                stroke="black"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </Link>
          <h2 className="font-satoshi font-medium text-xl md:text-2xl text-black">
            Add New Product
          </h2>
        </div>
        <div className="flex items-center gap-5">
          <Link
            href="/dashboard/products"
            className="font-satoshi font-medium text-sm text-[#858585] hover:text-black hover:font-semibold"
          >
            Cancel
          </Link>

          <button className="bg-[#fda600] outline-none font-satoshi font-medium text-black hover:text-[#fff] transition-colors duration-150 grow-0 p-2 md:px-5 md:py-2.5">
            Save changes
          </button>
        </div>
      </div>
      <h2 className="font-satoshi font-medium text-xl md:hidden text-black px-5">
        Add New Product
      </h2>
      <MultiStep />
    </div>
  );
};

export default page;
