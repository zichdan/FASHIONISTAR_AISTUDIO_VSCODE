import React from "react";
import VendorCard from "@/app/components/VendorCard";
// import { vendor } from "@/app/utils/mock";
import { getAllVendors } from "@/app/utils/libs";

const page = async () => {
  const vendors = (await getAllVendors()) || [];
  const vendor_list = vendors.map((vendor) => (
    <VendorCard vendorProp={vendor} key={vendor.id} />
  ));
  return (
    <div className="py-5 px-2 md:px-8 lg:px-28 ">
      <h2 className="text-[60px] font-bon_foyage  py-2 leading-10 text-black">
        {" "}
        Fashion Vendors
      </h2>

      <div className="bg-[#D9D9D9] w-full h-[58px]  px-5 gap-2 font-satoshi flex items-center">
        <svg
          width="20"
          height="20"
          viewBox="0 0 20 20"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M14.5833 14.5835L18.3333 18.3335"
            stroke="#282828"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M16.6667 9.1665C16.6667 5.02437 13.3089 1.6665 9.16675 1.6665C5.02461 1.6665 1.66675 5.02437 1.66675 9.1665C1.66675 13.3087 5.02461 16.6665 9.16675 16.6665C13.3089 16.6665 16.6667 13.3087 16.6667 9.1665Z"
            stroke="#282828"
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
        </svg>

        <input
          type="search"
          placeholder="Search for items..."
          className="placeholder:text-sm text-[#484848] placeholder:text-[#282828] outline-none w-full h-full bg-inherit"
        />
      </div>
      <div className=" relative flex justify-center items-center py-10  w-full">
        <div className="absolute left-0 font-satoshi font-medium text-sm leading-[19px] text-[#4e4e4e]">
          {" "}
          We have {vendors.length} Vendor(s) for you
        </div>
        <div className="absolute right-0 flex items-center gap-2 md:py-10 ">
          <div className="flex items-center gap-1  md:gap-2 py-1 px-1 md:py-2  md:px-[14px] rounded-[50px] border-[0.8px] border-[#959595]">
            <p className="text-[9px] leading-3 md:leading-6 md:text-base text-[#959595] font-satoshi">
              Sort by
            </p>
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M10.25 11.2449L11.3068 12.3598C11.8693 12.9533 12.1505 13.25 12.5 13.25C12.8495 13.25 13.1307 12.9533 13.6932 12.3598L14.75 11.2449M12.5 13.1846V9.90327C12.5 8.22815 12.5 7.39062 12.1649 6.6521C11.8297 5.91353 11.1994 5.36199 9.93875 4.25894L9.5 3.875"
                stroke="#959595"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M1.25 3.875C1.25 2.95617 1.25 2.49675 1.42882 2.1458C1.58611 1.83709 1.83709 1.58611 2.1458 1.42882C2.49675 1.25 2.95617 1.25 3.875 1.25C4.79383 1.25 5.25325 1.25 5.6042 1.42882C5.91291 1.58611 6.16389 1.83709 6.32119 2.1458C6.5 2.49675 6.5 2.95617 6.5 3.875C6.5 4.79383 6.5 5.25325 6.32119 5.6042C6.16389 5.91291 5.91291 6.16389 5.6042 6.32119C5.25325 6.5 4.79383 6.5 3.875 6.5C2.95617 6.5 2.49675 6.5 2.1458 6.32119C1.83709 6.16389 1.58611 5.91291 1.42882 5.6042C1.25 5.25325 1.25 4.79383 1.25 3.875Z"
                stroke="#959595"
              />
              <path
                d="M1.25 12.125C1.25 11.2062 1.25 10.7467 1.42882 10.3958C1.58611 10.0871 1.83709 9.83608 2.1458 9.6788C2.49675 9.5 2.95617 9.5 3.875 9.5C4.79383 9.5 5.25325 9.5 5.6042 9.6788C5.91291 9.83608 6.16389 10.0871 6.32119 10.3958C6.5 10.7467 6.5 11.2062 6.5 12.125C6.5 13.0438 6.5 13.5033 6.32119 13.8542C6.16389 14.1629 5.91291 14.4139 5.6042 14.5712C5.25325 14.75 4.79383 14.75 3.875 14.75C2.95617 14.75 2.49675 14.75 2.1458 14.5712C1.83709 14.4139 1.58611 14.1629 1.42882 13.8542C1.25 13.5033 1.25 13.0438 1.25 12.125Z"
                stroke="#959595"
              />
            </svg>
          </div>
          <div className="flex items-center gap-1  md:gap-2 py-1 px-1 md:py-2  md:px-[14px] rounded-[50px] border-[0.8px] border-[#959595]">
            <span className="text-[9px] leading-3 md:leading-6 md:text-base text-[#959595] font-satoshi">
              Filter
            </span>
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M10.25 11.2449L11.3068 12.3598C11.8693 12.9533 12.1505 13.25 12.5 13.25C12.8495 13.25 13.1307 12.9533 13.6932 12.3598L14.75 11.2449M12.5 13.1846V9.90327C12.5 8.22815 12.5 7.39062 12.1649 6.6521C11.8297 5.91353 11.1994 5.36199 9.93875 4.25894L9.5 3.875"
                stroke="#959595"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M1.25 3.875C1.25 2.95617 1.25 2.49675 1.42882 2.1458C1.58611 1.83709 1.83709 1.58611 2.1458 1.42882C2.49675 1.25 2.95617 1.25 3.875 1.25C4.79383 1.25 5.25325 1.25 5.6042 1.42882C5.91291 1.58611 6.16389 1.83709 6.32119 2.1458C6.5 2.49675 6.5 2.95617 6.5 3.875C6.5 4.79383 6.5 5.25325 6.32119 5.6042C6.16389 5.91291 5.91291 6.16389 5.6042 6.32119C5.25325 6.5 4.79383 6.5 3.875 6.5C2.95617 6.5 2.49675 6.5 2.1458 6.32119C1.83709 6.16389 1.58611 5.91291 1.42882 5.6042C1.25 5.25325 1.25 4.79383 1.25 3.875Z"
                stroke="#959595"
              />
              <path
                d="M1.25 12.125C1.25 11.2062 1.25 10.7467 1.42882 10.3958C1.58611 10.0871 1.83709 9.83608 2.1458 9.6788C2.49675 9.5 2.95617 9.5 3.875 9.5C4.79383 9.5 5.25325 9.5 5.6042 9.6788C5.91291 9.83608 6.16389 10.0871 6.32119 10.3958C6.5 10.7467 6.5 11.2062 6.5 12.125C6.5 13.0438 6.5 13.5033 6.32119 13.8542C6.16389 14.1629 5.91291 14.4139 5.6042 14.5712C5.25325 14.75 4.79383 14.75 3.875 14.75C2.95617 14.75 2.49675 14.75 2.1458 14.5712C1.83709 14.4139 1.58611 14.1629 1.42882 13.8542C1.25 13.5033 1.25 13.0438 1.25 12.125Z"
                stroke="#959595"
              />
            </svg>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap justify-between gap-3 gap-y-10 lg:gap-8 pb-10 ">
        {vendor_list}
      </div>
    </div>
  );
};

export default page;
