import Button from "@/app/components/Button";
import React from "react";

const page = () => {
  return (
    <>
      <div className="">
        <h2 className="font-satoshi font-medium text-3xl leading-10 text-black">
          Password Recovery
        </h2>
        <p className="font-satoshi py-3 text-[15px] leading-5 text-[#282828]">
          Enter your email address to recover your password
        </p>
      </div>
      <form>
        <div className="w-full flex flex-col gap-4 items-center relative py-7">
          <p className="flex items-center justify-start w-full gap-2 p-2">
            <label
              htmlFor="email"
              className="text-[15px] leading-5 text-[#101010] cursor-pointer"
            >
              Email Address
            </label>
          </p>
          <input
            type="email"
            name="email"
            id="email"
            className=" box-border bg-white outline-none w-full border-[1.5px] border-[#D9D9D9] rounded-[70px] p-4"
            placeholder="johndoe@gmail.com"
          />
        </div>
        {/* <button className="bg-[#FDA600] shd w-full outline-none py-[17px] text-white text-lg font-bold rounded-[70px]">
          Continue
        </button> */}
        <Button title="Continue" />
      </form>
    </>
  );
};

export default page;
