import React from "react";
import arrow from "../../../../public/arrows.svg";
import Image from "next/image";
import Link from "next/link";
import data, { data2 } from "@/app/utils/mock";
import Card from "@/app/components/Card";
import Cads from "@/app/components/Cads";

const page = () => {
  const collections = data.map((collection) => {
    return <Card data={collection} key={collection.title} />;
  });
  const deals = data2.map((card) => {
    return <Cads data={card} key={card.image} />;
  });
  return (
    <div className=" py-8 flex flex-col md:gap-10">
      <section className="flex flex-col gap-5 px-5 md:px-8 lg:px-28">
        <div className="flex justify-between items-center ">
          <h3 className="font-bon_foyage w-1/2 text-[40px] leading-[39.68px] md:text-[90px]  md:leading-[89px] text-black md:w-[380px]">
            Fashion Categories
          </h3>
          <div className="flex items-center gap-2">
            <button className="w-[30px] h-[30px] rounded-full ">
              <Image src={arrow} alt="" />
            </button>
            <button className="w-[30px] h-[30px] rounded-full">
              <Image src={arrow} alt="" className="scale-x-[-1]" />
            </button>
          </div>
        </div>
        <div className="">
          <ul className="w-full flex items-center justify-between md:justify-start gap-2 md:gap-6 font-satoshi text-white md:text-[22px] text-[8.77px] leading-[11.83px] md:leading-[30px]">
            <Link
              href="/"
              className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px]  bg-[#fda600]"
            >
              All
            </Link>

            <li className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px]  bg-[#fda600]">
              Vintage clothing
            </li>
            <li className="py-[9px] px-[13.95px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-[#fda600]">
              Senator
            </li>
            <li className="py-[9px] px-[13.95px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-[#fda600]">
              Minimalist
            </li>
            <li className="py-[9px] px-[13.95px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-[#fda600]">
              {" "}
              Casual
            </li>
          </ul>
        </div>
        <div className="flex flex-wrap justify-center gap-4 gap-y-10 md:gap-4 lg:gap-8  ">
          {collections}
        </div>
      </section>
      <section className="px-5 md:px-8 lg:px-28 flex flex-col gap-10 py-[70px]">
        <div className="flex justify-between items-center">
          <h3 className="font-bon_foyage w-1/2 text-[40px] leading-[39.68px] md:text-[90px]  md:leading-[89px] text-black md:w-[380px]">
            Deals of the
            <br /> day
          </h3>
          <Link
            href="/"
            className="flex items-center font-satoshi md:text-2xl text-[13px] text-[#4e4e4e]"
          >
            All Deals
            <svg
              width="20"
              height="20"
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M7.50004 5C7.50004 5 12.5 8.68242 12.5 10C12.5 11.3177 7.5 15 7.5 15"
                stroke="#4E4E4E"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </Link>
        </div>
        <div className="flex flex-wrap justify-center gap-4 lg:gap-8 ">
          {deals}
        </div>
      </section>
    </div>
  );
};

export default page;
