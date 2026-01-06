import React from "react";
import { usePathname } from "next/navigation";
import Image from "next/image";

const AdminTopBanner = ({
  title,
  pathname,
}: {
  title: string;
  pathname: string;
}) => {
  return (
    <div className="hidden lg:flex items-center justify-between  h-[122px] px-10 bg-white fixed top-0 right-0 w-[75%] z-50">
      <div className="flex items-center gap-2">
        <Image
          src="/woman3.svg"
          alt=""
          height={50}
          width={50}
          className="rounded-full h-[45px] w-[45px] object-cover"
        />
        <div>
          <h2 className="font-satoshi font-medium text-2xl text-black">
            Welcome Back!
          </h2>
          <span className="text-xl text-black ">{title}</span>
        </div>
      </div>
      <div
        className={`items-center  md:w-[55%] lg:w-[574px] h-[60px] bg-[#d9d9d9] px-4 gap-6 ${
          pathname == "/admin-dashboard" ? "hidden" : "flex"
        }`}
      >
        <span className="block transition-all peer-focus:hidden">
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M13.125 13.125L16.5 16.5"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M15 8.25C15 4.52208 11.978 1.5 8.25 1.5C4.52208 1.5 1.5 4.52208 1.5 8.25C1.5 11.978 4.52208 15 8.25 15C11.978 15 15 11.978 15 8.25Z"
              stroke="#282828"
              strokeLinejoin="round"
            />
          </svg>
        </span>

        <input
          type="search"
          placeholder="Search"
          className="w-full bg-[#d9d9d9] outline-none focus:outline-none peer"
        />
      </div>
      <div className="flex items-center gap-1">
        <button className="w-8 h-8 flex justify-center items-center bg-white">
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M3.86878 8.61825C3.81367 9.66525 3.87702 10.7798 2.9416 11.4813C2.50623 11.8079 2.25 12.3203 2.25 12.8645C2.25 13.6131 2.83635 14.25 3.6 14.25H14.4C15.1637 14.25 15.75 13.6131 15.75 12.8645C15.75 12.3203 15.4938 11.8079 15.0584 11.4813C14.1229 10.7798 14.1863 9.66525 14.1312 8.61825C13.9876 5.88917 11.7329 3.75 9 3.75C6.26713 3.75 4.01241 5.88917 3.86878 8.61825Z"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M7.875 2.34375C7.875 2.96507 8.3787 3.75 9 3.75C9.6213 3.75 10.125 2.96507 10.125 2.34375C10.125 1.72243 9.6213 1.5 9 1.5C8.3787 1.5 7.875 1.72243 7.875 2.34375Z"
              stroke="#282828"
            />
            <path
              d="M11.25 14.25C11.25 15.4927 10.2427 16.5 9 16.5C7.75732 16.5 6.75 15.4927 6.75 14.25"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        {pathname === "/admin-dashboard" ? (
          <button className="w-8 h-8 flex justify-center items-center bg-white">
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M13.125 13.125L16.5 16.5"
                stroke="#282828"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M15 8.25C15 4.52208 11.978 1.5 8.25 1.5C4.52208 1.5 1.5 4.52208 1.5 8.25C1.5 11.978 4.52208 15 8.25 15C11.978 15 15 11.978 15 8.25Z"
                stroke="#282828"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        ) : (
          <div className="flex flex-col items-center">
            <span className="font-medium text-[13px] leading-[18px] text-black">
              {" "}
              Wallet balance
            </span>
            <span className="text-black text-2xl font-medium font-satoshi">
              {" "}
              $12
            </span>
          </div>
        )}
        {/* <button className="w-8 h-8 flex justify-center items-center bg-white">
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M13.125 13.125L16.5 16.5"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M15 8.25C15 4.52208 11.978 1.5 8.25 1.5C4.52208 1.5 1.5 4.52208 1.5 8.25C1.5 11.978 4.52208 15 8.25 15C11.978 15 15 11.978 15 8.25Z"
              stroke="#282828"
              strokeLinejoin="round"
            />
          </svg>
        </button> */}
      </div>
    </div>
  );
};

export default AdminTopBanner;
