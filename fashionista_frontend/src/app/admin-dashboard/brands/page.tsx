import React from "react";
import Link from "next/link";
import sapphire from "../../../../public/vendor/sapphire.svg";
import burberry from "../../../../public/vendor/burberry.svg";
import ralph from "../../../../public/vendor/ralph.svg";
import calvin from "../../../../public/vendor/calvin.svg";
import { vendor } from "@/app/utils/mock";
import Image from "next/image";

const page = () => {
  const vendorList = vendor.map((item) => {
    return (
      <div
        key={item.name}
        className="w-[48%] md:w-[30%] lg:w-[24%] flex flex-col hover:shadow-md group z-0"
      >
        <div className="w-full h-[217px] md:h-[320px] overflow-hidden">
          <Image
            src={item.image}
            alt={item.name}
            className="w-full h-full object-cover group-hover:scale-105 transition ease-in-out duration-200"
          />
        </div>
        <div className="px-1 pt-3 pb-10 hover:bg-gray-50">
          <p className="font-bon_foyage text-[26px] leading-6 text-black">
            {item.name}
          </p>

          <p className="font-satoshi   text-[#282828]">{item.rating} items</p>
        </div>
      </div>
    );
  });
  return (
    <div className="space-y-10 pb-10">
      <div className="flex flex-wrap items-center justify-between space-y-3">
        <div>
          <h3 className="font-satoshi font-medium text-3xl text-black">
            Brands
          </h3>
          <p className="font-satoshi text-sm text-[#4E4E4E]">
            Brands and vendors management
          </p>
        </div>
        <div className="flex items-center gap-4 ">
          <Link
            href="/dashboard/products"
            className="bg-[#fda600] hover:bg-black flex items-center font-satoshi font-medium text-black hover:text-[#fda600] transition-colors duration-150 grow-0  px-5 py-2.5"
          >
            Add New Brand
          </Link>
        </div>
      </div>
      <div className="w-full bg-white rounded-[20px] min-h-[400px] p-3 md:p-[30px] space-y-5">
        <div className="flex items-center justify-end gap-3">
          <div className="p-2.5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="All Categories"
            >
              <option disabled className="">
                All Categories
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
              defaultValue="latest Added"
            >
              <option disabled className="">
                latest Added
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
        </div>
        <div className="flex flex-wrap justify-center gap-x-3 gap-y-10 pb-10 ">
          {vendorList}
        </div>
      </div>
    </div>
  );
};

export default page;
