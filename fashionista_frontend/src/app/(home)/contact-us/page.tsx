import Image from "next/image";
import React from "react";
import girl from "../../../../public/girl2.svg";

const page = () => {
  return (
    <div className="px-4 md:px-[100px] flex flex-col gap-4  pb-10">
      <h2 className="font-satoshi font-medium text-[#fda600] md:text-2xl">
        How can we help you ?
      </h2>
      <div className="flex flex-col md:flex-row md:justify-between ">
        <div className="flex flex-col gap-3 w-full md:w-[30%]">
          <h2 className="font-bon_foyage text-[32px] md:text-5xl md:leading-[48px] leading-8 text-black">
            Let us know where we can help you
          </h2>
          <p className="font-satoshi text-sm md:text-[20px] md:leading-[27px] leading-[19px] text-[#282828]">
            Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
            consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
            mauris elit fames amet.
          </p>
        </div>
        <div className="flex flex-col md:flex-row md:flex-wrap md:gap-y-5 justify-between w-full md:w-[67%]">
          <div className="flex flex-col gap-2 md:w-[47%]">
            <h2 className="font-bon_foyage text-[32px] leading-8 text-black">
              Visit Feedback
            </h2>
            <p className="font-satoshi text-sm md:text-[20px] md:leading-[27px] leading-[19px] text-[#282828]">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="flex flex-col gap-2 md:w-[47%]">
            <h2 className="font-bon_foyage text-[32px] leading-8 text-black">
              Billings Enquiries
            </h2>
            <p className="font-satoshi text-sm md:text-[20px] md:leading-[27px] leading-[19px] text-[#282828]">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="flex flex-col gap-2 md:w-[47%]">
            <h2 className="font-bon_foyage text-[32px] leading-8 text-black">
              Employers Services
            </h2>
            <p className="font-satoshi text-sm md:text-[20px] md:leading-[27px] leading-[19px] text-[#282828]">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="flex flex-col gap-2 md:w-[47%]">
            <h2 className="font-bon_foyage text-[32px] leading-8 text-black">
              General Enquiries
            </h2>
            <p className="font-satoshi text-sm md:text-[20px] md:leading-[27px] leading-[19px] text-[#282828]">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
        </div>
      </div>

      <div>
        <div className="flex flex-col gap-2">
          <p className="font-satoshi font-medium text-[#fda600]">
            Contact Form
          </p>
          <h3 className="text-[32px] font-bon_foyage leading-8 text-black">
            Drop us a Line
          </h3>
          <span className="text-[#282828] leading-[19px] text-sm font-satoshi">
            Your email will not be published. Required fields are marked.
          </span>
        </div>

        <div className="flex justify-between items-center">
          <form className="flex flex-col w-full gap-5 md:w-1/2">
            <div className="bg-[#d9d9d9] w-full ">
              <input
                type="text"
                className="w-full px-5 py-4 bg-inherit placeholder:text-[#282828] text-[#282828] outline-none"
                placeholder="Full Name"
              />
            </div>
            <div className="bg-[#d9d9d9] w-full ">
              <input
                type="email"
                className="w-full px-5 py-4 bg-inherit placeholder:text-[#282828] text-[#282828] outline-none"
                placeholder="Email Address"
              />
            </div>
            <div className="bg-[#d9d9d9] w-full ">
              <input
                type="tel"
                className="w-full px-5 py-4 bg-inherit placeholder:text-[#282828] text-[#282828] outline-none"
                placeholder="Phone Number"
              />
            </div>
            <div className="bg-[#d9d9d9] w-full h-[148px] md:h-[217px] ">
              <textarea
                className="w-full h-full px-4 py-4 bg-inherit placeholder:text-[#282828] text-[#282828] outline-none"
                placeholder="Message"
              />
            </div>
            <div className="flex justify-center items-center">
              <button className="text-[#282828] leading-6 text-lg font-medium font-satoshi bg-[#fda600] w-1/2 h-[55px]">
                Send Message
              </button>
            </div>
          </form>
          <div className="hidden md:flex">
            <Image src={girl} alt="" />
          </div>
        </div>
      </div>
    </div>
  );
};

export default page;
