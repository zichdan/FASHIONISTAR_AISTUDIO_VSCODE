import React from "react";
import heroImg from "../../../public/heroimg.png";
import Image from "next/image";
import Link from "next/link";

const Hero = () => {
  return (
    <div className="flex flex-col lg:flex-row items-center relative">
      <div className="h-full min-h-[430px] md:h-[686px] w-full lg:min-w-[90%]   bg-[#fda600] lg:rounded-br-[80px] flex flex-col justify-center items-center relative overflow-hidden">
        <Link
          // type="button"
          href="/get-measured"
          className="w-[144px] flex justify-center items-center absolute top-6 right-6 h-[43px] font-semibold font-raleway rounded-[100px] bg-[#01454a] text-white shrink-0"
        >
          Get Measured
        </Link>
        <div className="w-full pl-5 md:pl-10 lg:pl-24 flex flex-col gap-5 justify-center ">
          <h2 className="font-bon_foyage lg:whitespace-nowrap text-[35px] leading-[44px] md:text-[75px] md:leading-[86px] text-black inline-block">
            {" "}
            Unlock Your Fashion <br /> Essence With{" "}
            <span className="text-white bg-[#01454a] w-full px-2 pr-10 inline-block">
              Fashionistar
            </span>
          </h2>
          <p className="font-raleway font-semibold  md:text-2xl text-black">
            Early adaptors get free trials
          </p>
          <form className="hidden md:flex z-30">
            <div className="h-[60px] lg:h-[85px] w-full md:w-1/2 bg-[#F4F5FB] rounded-r-[100px] flex items-center p-1.5 lg:p-3">
              <input
                type="email"
                className="w-2/3 h-full outline-none bg-inherit placeholder:not-italic placeholder:font-raleway placeholder:font-medium placeholder:text-xl placeholder:text-[#333] text-[#333]"
                placeholder="Enter Email Address"
              />

              <button className="w-1/3 lg:min-h-[66px] h-full rounded-r-[100px] bg-[#01454a] text-white shrink-0 text-sm lg:text-xl font-bold font-raleway">
                Join Waitlist
              </button>
            </div>
          </form>
          <button
            type="button"
            className="w-[144px] h-[43px] font-semibold font-raleway rounded-[100px] bg-[#01454a] text-white shrink-0"
          >
            Shop now
          </button>
        </div>
        {/*  w-[270px] h-[300px] md:w-[505px] md:h-[550px] */}
        <div className="absolute -right-3 -bottom-5 lg:right-0 lg:bottom-0">
          <Image
            src={heroImg}
            alt=""
            className="w-[275px] h-[300px] md:w-[505px] md:h-[550px] max-w-full"
          />
        </div>
      </div>
      {/* Carousel btn */}
      <div className="gap-2 md:gap-4 z-30 w-full -mt-20 md:mt-0 p-5 flex justify-center lg:justify-normal lg:flex-col ">
        <div className="w-2.5 h-2.5 md:w-6 md:h-6 rounded-full bg-white md:bg-[#01454A] border-2 border[#d9d9d9] shadow" />
        <div className="w-2.5 h-2.5 md:w-6 md:h-6 rounded-full bg-transparent md:bg-[#f5f5f5] border-2 border[#d9d9d9] shadow" />
        <div className="w-2.5 h-2.5 md:w-6 md:h-6 rounded-full bg-transparent md:bg-[#f5f5f5] border-2 border[#d9d9d9] shadow" />
      </div>
    </div>
  );
};

export default Hero;
