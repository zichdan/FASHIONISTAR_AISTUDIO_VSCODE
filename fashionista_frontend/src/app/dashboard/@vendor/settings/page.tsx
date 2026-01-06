import TopBanner from "@/app/components/TopBanner";
import Image from "next/image";
import React from "react";
import DragAndDrop from "@/app/components/DragAndDrop";

interface VendorProp {
  image: string;
  vendor: string;
  url: string;
  business_mail: string;
  address: string;
  state: string;
}
const page = () => {
  const vendor: VendorProp = {
    image: "/vendor/sapphire.svg",
    vendor: "Sapphire",
    url: "@sapphirecollections",
    business_mail: "sapphirecollection@mail.com",
    address: "Somewhere on earth",
    state: "Lagos state",
  };
  return (
    <div className="mt-[125px] px-[30px]">
      <TopBanner title="Settings" />
      <div className="flex items-center gap-4">
        <div className="w-[118px] h-[118px] rounded-full bg-[#fda600]">
          <Image
            src={vendor.image}
            width={100}
            height={100}
            alt={vendor.vendor}
            className="w-full h-full rounded-full "
          />
        </div>
        <div>
          <h2 className="font-satoshi font-medium text-2xl text-black">
            {vendor.vendor}
          </h2>
          <p className="font-satoshi font-medium text-[#4E4E4E]">
            {vendor.url}
          </p>
        </div>
      </div>
      <form className="w-10/12 mx-auto flex flex-wrap gap-x-4 gap-y-10  py-6">
        <div className="flex flex-col gap-2 w-full md:w-[48%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Business Mail
          </label>
          <input
            type="text"
            name="shipping_amount"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full bg-inherit px-4 outline-none text-[#000]"
          />
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[48%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Business Name
          </label>
          <input
            type="text"
            name="shipping_amount"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full bg-inherit px-4 outline-none text-[#000]"
          />
        </div>
        <div className="flex items-start justify-between w-full ">
          <div className="w-[62px] h-[62px] rounded-full bg-[#fda600]">
            <Image
              src={vendor.image}
              width={100}
              height={100}
              alt={vendor.vendor}
              className="w-full h-full rounded-full "
            />
          </div>
          <DragAndDrop />
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[48%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            State
          </label>
          <input
            type="text"
            name="shipping_amount"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full bg-inherit px-4 outline-none text-[#000]"
          />
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[48%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Contact Address
          </label>
          <input
            type="text"
            name="shipping_amount"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full bg-inherit px-4 outline-none text-[#000]"
          />
        </div>
        <div className="flex items-center justify-end gap-8 w-full py-8">
          <button className="font-medium text-lg leading-6 text-[#4E4E4E] hover:text-black">
            Cancel
          </button>

          <button className="py-2 px-5 bg-[#fda600] outline-none font-medium text-black hover:text-white grow-0">
            Save Changes
          </button>
        </div>
      </form>
    </div>
  );
};

export default page;
