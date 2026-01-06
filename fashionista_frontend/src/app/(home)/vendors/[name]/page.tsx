import React from "react";
import Image from "next/image";
import Link from "next/link";
import instagram from "../../../../../public/socials/instagram.svg";
import twitter from "../../../../../public/socials/twitter.svg";
import facebook from "../../../../../public/socials/facebook.svg";
import Card from "@/app/components/Card";
import Cads from "@/app/components/Cads";
import data, { data2 } from "@/app/utils/mock";

interface NameProp {
  params: {
    name: string;
  };
}

const page = ({ params }: NameProp) => {
  const { name } = params;
  const collections = data.map((collection) => {
    return <Card data={collection} key={collection.title} />;
  });
  const deals = data2.map((card) => {
    return <Cads data={card} key={card.image} />;
  });
  return (
    <div className="px-5 md:px-8 lg:px-28 flex flex-col gap-4 pb-8">
      <h2 className="font-bon_foyage text-[40px] leading-[39.68px] md:text-[75px] md:leading-[75px]  lg:text-[90px]  lg:leading-[89px] text-black lg:w-1/2">
        {" "}
        {decodeURIComponent(name)}
        <span className="text-[#fda600] block">Store</span>
      </h2>
      <div className="w-full md:w-2/3 lg:w-1/2 h-[195px] md:h-[356px] bg-[#DED4CA] p-4 flex flex-col justify-between">
        <p className="font-satoshi text-xs md:text-[22px] md:leading-[29.7px] text-[#282828]">
          Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
          consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at mauris
          elit fames amet.
        </p>
        <div>
          <p className="font-satoshi font-medium text-xs md:text-[22px] md:leading-[29.7px] text-black">
            {" "}
            Follow Us
          </p>
          <div className="flex items-center gap-2">
            <a
              href="/"
              target="_blank"
              className="w-5 h-5 md:w-[25px] md:h-[25px] bg-[#fda600] flex justify-center items-center rounded-full"
            >
              <Image
                src={twitter}
                alt=""
                className="w-[80%] h-[80%] max-h-auto object-cover"
              />
            </a>
            <a
              href="/"
              target="_blank"
              className="w-5 h-5 md:w-[25px]  md:h-[25px] bg-[#fda600] flex justify-center items-center rounded-full"
            >
              <Image
                src={instagram}
                alt=""
                className="w-full h-full object-cover"
              />
            </a>
            <a
              href="/"
              target="_blank"
              className="w-5 h-5 md:w-[25px] md:h-[25px] bg-[#fda600] flex justify-center items-center rounded-full"
            >
              <Image
                src={facebook}
                alt=""
                className="w-full h-full object-cover"
              />
            </a>
          </div>
        </div>
        <p className="font-satoshi text-[10px] leading-[13px]  md:text-lg md:leading-6 text-black flex items-center gap-2">
          <svg
            width="11"
            height="11"
            viewBox="0 0 20 20"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              fillRule="evenodd"
              clip-rule="evenodd"
              d="M7.40945 17.5655L7.45512 17.6095L7.4587 17.613C8.29556 18.4149 9.10696 18.9646 10.0247 18.954C10.9383 18.9435 11.7464 18.3795 12.5827 17.5652C13.729 16.4545 15.2121 14.9563 16.2836 13.179C17.3592 11.395 18.0533 9.27425 17.531 6.94654C15.7665 -0.920188 4.24281 -0.929405 2.46901 6.93819C1.96156 9.19992 2.60266 11.2688 3.62503 13.0223C4.64356 14.7692 6.06871 16.2523 7.21166 17.3725C7.27826 17.4378 7.34398 17.5018 7.40866 17.5648L7.40945 17.5655ZM10 5.20835C8.50429 5.20835 7.29171 6.42092 7.29171 7.91669C7.29171 9.41242 8.50429 10.625 10 10.625C11.4958 10.625 12.7084 9.41242 12.7084 7.91669C12.7084 6.42092 11.4958 5.20835 10 5.20835Z"
              fill="#000"
            />
          </svg>
          Address: 507a, Festac W, Ikate, Lagos State.
        </p>
        <p className="font-satoshi text-[10px] leading-[13px]  md:text-lg md:leading-6 text-black flex items-center gap-2">
          <svg
            width="11"
            height="11"
            viewBox="0 0 20 20"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M12.5 10.0002C12.5 9.07966 13.2462 8.3335 14.1667 8.3335C16.0076 8.3335 17.5 9.82591 17.5 11.6668C17.5 13.5077 16.0076 15.0002 14.1667 15.0002C13.2462 15.0002 12.5 14.254 12.5 13.3335V10.0002Z"
              stroke="#000"
              strokeWidth="1.5"
            />
            <path
              d="M7.5 10.0002C7.5 9.07966 6.75381 8.3335 5.83333 8.3335C3.99238 8.3335 2.5 9.82591 2.5 11.6668C2.5 13.5077 3.99238 15.0002 5.83333 15.0002C6.75381 15.0002 7.5 14.254 7.5 13.3335V10.0002Z"
              stroke="#000"
              strokeWidth="1.5"
            />
            <path
              d="M2.5 11.6665V9.1665C2.5 5.02437 5.85787 1.6665 10 1.6665C14.1422 1.6665 17.5 5.02437 17.5 9.1665V13.205C17.5 14.8786 17.5 15.7153 17.2063 16.3679C16.8721 17.1106 16.2774 17.7053 15.5348 18.0395C14.8822 18.3332 14.0454 18.3332 12.3718 18.3332H10"
              stroke="#000"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          Call Us On: +234 90 0000 000
        </p>
      </div>
      <div className="bg-[#D9D9D9] w-full md:w-2/3 lg:w-1/2 h-[58px]  px-5 gap-2 font-satoshi flex items-center justify-center">
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
      <div>
        <p className="font-satoshi font-medium text-sm text-[#4E4E4E] py-4">
          We have 22 items for you
        </p>
        <div className="flex flex-wrap justify-center gap-4 gap-y-10 lg:gap-8">
          {collections}
        </div>
      </div>
      <section className=" flex flex-col gap-10 pt-[50px]">
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
        <div className="flex flex-wrap justify-center gap-4 gap-y-4 lg:gap-8 ">
          {deals}
        </div>
      </section>
    </div>
  );
};

export default page;
