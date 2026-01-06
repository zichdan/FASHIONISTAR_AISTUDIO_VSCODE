import React from "react";
import Link from "next/link";
import Image from "next/image";
import Card from "@/app/components/Card";
import data from "@/app/utils/mock";
import arrow from "../../../../public/arrows.svg";
import { blog } from "@/app/utils/mock";
import BlogCard from "@/app/components/BlogCard";

const page = () => {
  const collections = data.map((collection) => {
    return <Card data={collection} key={collection.title} />;
  });
  const blogList = blog.map((blog, index) => (
    <BlogCard key={index} blog={blog} />
  ));
  return (
    <div className="px-5 md:px-8 lg:px-28 flex flex-col gap-10 ">
      <div>
        <h3 className="font-bon_foyage w-1/2 text-[40px] leading-[39.68px] md:text-[90px]  md:leading-[89px] text-black md:w-[380px]">
          Blog
        </h3>
        <p className="font-satoshi font-medium text-xs text-[#4e4e4e]">
          {" "}
          Here is the information about trendy fashions. How to keep up with the
          latest fashion? How to dress best? You will find everything here!
        </p>
      </div>
      <section className="flex flex-col gap-5 ">
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
          <ul className="w-full flex items-center justify-between md:justify-start gap-2 md:gap-6 font-satoshi text-[#fda600] md:text-[22px] text-[8.77px] leading-[11.83px] md:leading-[30px]">
            <Link
              href="/"
              className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-inherit hover:text-white  border  border-[#fda600]  hover:bg-[#fda600]"
            >
              All
            </Link>

            <li className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px]  bg-inherit hover:text-white border  border-[#fda600]  hover:bg-[#fda600]">
              Vintage clothing
            </li>
            <li className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-inherit hover:text-white border  border-[#fda600]  hover:bg-[#fda600]">
              Senator
            </li>
            <li className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-inherit hover:text-white border  border-[#fda600]  hover:bg-[#fda600]">
              Minimalist
            </li>
            <li className="py-[9px] px-[12px] md:py-[15px] md:px-[35px] rounded-[15px] md:rounded-[50px] bg-inherit hover:text-white border  border-[#fda600]  hover:bg-[#fda600]">
              {" "}
              Casual
            </li>
          </ul>
        </div>
        <div className="flex flex-wrap justify-center gap-4 gap-y-10 md:gap-4 lg:gap-8  ">
          {collections}
        </div>
      </section>
      <section className="flex flex-col gap-4 min-h-[500px]">
        <div className="flex items-center justify-between">
          <h2 className="font-bon_foyage text-[30px] leading-[30px] text-black">
            Articles
          </h2>
          <div className="w-[78px] h-[25px] flex justify-center items-center gap-2 border-[0.66px] border-[#4e4e4e] rounded-[32.77px]">
            <span className="font-satoshi text-[11px] leading-[14px] text-[#4e4e4e]">
              Sort by
            </span>
            <svg
              width="11"
              height="12"
              viewBox="0 0 11 12"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M8.20186 4.68899C8.20186 4.68899 6.27091 7.31081 5.58001 7.31081C4.88906 7.31081 2.95816 4.68896 2.95816 4.68896"
                stroke="#282828"
                strokeWidth="0.655462"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
        </div>
        {blogList}
        <div>Pagination</div>
      </section>
    </div>
  );
};

export default page;
