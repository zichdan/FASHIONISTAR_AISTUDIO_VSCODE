"use client";
import React from "react";

const page = () => {
  const handleMeasurement = async () => {
    try {
      const res = await fetch("");
    } catch (error) {
      console.log(error);
    }
  };
  return (
    <div className="py-10 px-5 md:px-24">
      <h2 className="font-bon_foyage pb-3 border-b-[1.5px] border-[#D9D9D9] text-[40px] leading-10 md:text-7xl text-black">
        Measurement
      </h2>
      <div className="flex flex-col md:flex-row justify-between gap-5 py-5">
        <div className=" w-full md:w-1/2  space-y-4">
          <p className="font-raleway text-2xl text-black">
            Watch video for guidelines on measurement taking
          </p>
          <div
            className="relative w-full h-[468px] rounded-2xl border-4 border-[#F4F5FB]"
            style={{ boxShadow: "0px 2px 2px 0px #00000040" }}
          >
            <iframe
              className="absolute top-0 left-0 w-full h-full rounded-2xl"
              src={`https://www.youtube.com/embed/sk8eb2nW_ds`}  // Corrected embed link
              title="How to take your measurement on Fashionistar"
              frameBorder="0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
            ></iframe>
          </div>
        </div>
        <div className="border border-[#d9d9d9] p-5 md:p-[30px] flex flex-col justify-between  rounded-[10px] max-w-[529px] w-full min-h-[25rem] h-full md:h-[735px]">
          <div className="space-y-5">
            <p className="font-raleway border-b-[1.5px] border-[#D9D9D9] py-3 text-2xl leading-10 font-medium text-black">
              Measurement
            </p>
            <p className="font-raleway font-medium text-xl text-black">
              {" "}
              Your measurement here
            </p>
            <p className="px-2 md:px-4 py-3 bg-[#F4F5FB] rounded-[14px] font-satoshi text-lg md:text-2xl text-[#475367] flex-none grow">
              A token of #1000 will be deducted from your balance from each
              measurement your take
            </p>
          </div>
          <button
            onClick={handleMeasurement}
            className="w-full h-[60px] text-black bg-[#fda600] font-bold font-satoshi flex items-center justify-center text-xl"
          >
            Take Your Measurement
          </button>
        </div>
      </div>
    </div>
  );
};

export default page;
