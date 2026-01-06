"use client";
import React, { useState, useEffect } from "react";
import menu from "../../../public/menu.svg";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";

const MobileNavBar = () => {
  const pathname = usePathname();
  const [showNav, setShowNav] = useState<boolean>(false);
  useEffect(() => {
    setShowNav(false);
  }, [pathname]);
  return (
    <div className="flex justify-between items-center bg-[#F1D858] rounded-[5px] md:hidden px-1">
      <div
        className={`absolute top-0 w-full transition-all ease-in-out duration-150  flex flex-col justify-between min-h-screen bg-[#fff] z-50 ${
          showNav ? "left-0" : "-left-[100%]"
        }`}
      >
        <div className="flex justify-between items-center py-6 px-5 border-b border-[#d9d9d9]">
          <div className="flex items-center">
            <Image src="/logo.svg" alt="logo" width={46} height={45} />
            <h2 className="font-bon_foyage px-3 text-3xl leading-9 text-black">
              Fashionistar
            </h2>
          </div>
          <button
            onClick={() => setShowNav(false)}
            className=" w-6 h-6 flex justify-center items-center"
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M15.8334 4.1665L4.16675 15.8332M4.16675 4.1665L15.8334 15.8332"
                stroke="#282828"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        </div>
        <div className="px-5">
          <div className="bg-[#D9D9D9] w-full h-[58px]  px-5 gap-2 font-satoshi flex items-center">
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
        </div>

        <nav className="z-50 relative flex  flex-col gap-4 justify-between px-4 font-satoshi w-full h-1/2">
          <Link
            href="/"
            className={`text-[#282828] leading-5 ${
              pathname === "/"
                ? "font-medium text-base"
                : " font-normal text-sm "
            } `}
          >
            Home
          </Link>
          <Link
            href="/about-us"
            className={`text-[#282828] leading-5 ${
              pathname === "/about-us"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            About
          </Link>
          <Link
            href="/categories"
            className={`text-[#282828] leading-5 ${
              pathname === "/categories"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Categories
          </Link>
          <Link
            href="/vendor"
            className={`text-[#282828] leading-5 ${
              pathname === "/vendor"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Vendors
          </Link>
          <Link
            href="/shops"
            className={`text-[#282828] leading-5  ${
              pathname === "/shops"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Shops
          </Link>
          <Link
            href="/collections"
            className={`text-[#282828] leading-5 ${
              pathname === "/collections"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Collections
          </Link>
          <Link
            href="/testimonails"
            className={`text-[#282828] leading-5 ${
              pathname === "/testimonails"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Testimonials
          </Link>
          <Link
            href="/contact-us"
            className={`text-[#282828] leading-5 ${
              pathname === "/contact-us"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Contact Us
          </Link>
          <Link
            href="/blog"
            className={`text-[#282828] leading-5 ${
              pathname === "/blog"
                ? "text-base font-medium"
                : "text-sm font-normal "
            } `}
          >
            Blog
          </Link>

          {/* <div className="flex flex-col">
            <div className="flex items-center">
              <svg
                width="30"
                height="30"
                viewBox="0 0 30 30"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M18.75 15C18.75 13.6193 19.8693 12.5 21.25 12.5C24.0114 12.5 26.25 14.7386 26.25 17.5C26.25 20.2614 24.0114 22.5 21.25 22.5C19.8693 22.5 18.75 21.3807 18.75 20V15Z"
                  stroke="black"
                  strokeWidth="1.5"
                />
                <path
                  d="M11.25 15C11.25 13.6193 10.1307 12.5 8.75 12.5C5.98857 12.5 3.75 14.7386 3.75 17.5C3.75 20.2614 5.98857 22.5 8.75 22.5C10.1307 22.5 11.25 21.3807 11.25 20V15Z"
                  stroke="black"
                  strokeWidth="1.5"
                />
                <path
                  d="M3.75 17.5V13.75C3.75 7.5368 8.7868 2.5 15 2.5C21.2133 2.5 26.25 7.5368 26.25 13.75V19.8077C26.25 22.3181 26.25 23.5733 25.8095 24.5521C25.3081 25.6661 24.4161 26.5581 23.3021 27.0595C22.3233 27.5 21.0681 27.5 18.5577 27.5H15"
                  stroke="black"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <span className="font-medium text-xl px-2 leading-[27px] text-black w-[127px]">
                +234 90 0000 000
              </span>
            </div>

            <div className="flex justify-end ">
              <span className="text-black pr-2 leading-4 text-xs font-medium ">
                24/7 support center
              </span>
            </div>
          </div> */}
        </nav>
        <div className="px-4 flex flex-col gap-4 justify-end  h-full">
          <div className="flex items-center gap-1">
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M4.93318 11.6112C3.8721 12.243 1.09002 13.5331 2.7845 15.1475C3.61223 15.936 4.53412 16.5 5.69315 16.5H12.3068C13.4659 16.5 14.3878 15.936 15.2155 15.1475C16.91 13.5331 14.1279 12.243 13.0668 11.6112C10.5786 10.1296 7.42139 10.1296 4.93318 11.6112Z"
                stroke="#282828"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M12.375 4.875C12.375 6.73896 10.864 8.25 9 8.25C7.13604 8.25 5.625 6.73896 5.625 4.875C5.625 3.01104 7.13604 1.5 9 1.5C10.864 1.5 12.375 3.01104 12.375 4.875Z"
                stroke="#282828"
              />
            </svg>
            <span className="text-[#282828] text-[15px] font-satoshi">
              Accounts
            </span>
          </div>
          <div className="flex items-center gap-1">
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M11.25 9C11.25 8.17155 11.9216 7.5 12.75 7.5C14.4068 7.5 15.75 8.84317 15.75 10.5C15.75 12.1568 14.4068 13.5 12.75 13.5C11.9216 13.5 11.25 12.8284 11.25 12V9Z"
                stroke="#282828"
              />
              <path
                d="M6.75 9C6.75 8.17155 6.07843 7.5 5.25 7.5C3.59314 7.5 2.25 8.84317 2.25 10.5C2.25 12.1568 3.59314 13.5 5.25 13.5C6.07843 13.5 6.75 12.8284 6.75 12V9Z"
                stroke="#282828"
              />
              <path
                d="M2.25 10.5V8.25C2.25 4.52208 5.27208 1.5 9 1.5C12.728 1.5 15.75 4.52208 15.75 8.25V11.8846C15.75 13.3909 15.75 14.144 15.4857 14.7313C15.1849 15.3997 14.6497 15.9349 13.9813 16.2357C13.394 16.5 12.6409 16.5 11.1346 16.5H9"
                stroke="#282828"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span className="text-[#282828] text-[15px] font-satoshi">
              +23490000000
            </span>
          </div>
        </div>
      </div>
      <button
        onClick={() => setShowNav(true)}
        className="w-[34px] h-[34px] flex justify-center  items-center bg-[#F4F3EC] border-[0.8px] border-black rounded-full"
      >
        <Image src={menu} alt="" />
      </button>
      <div className="flex items-center">
        <Image src="/logo.svg" alt="logo" width={39} height={38} />
        <h2 className="font-bon_foyage px-3 text-2xl leading-6 text-black">
          Fashionistar
        </h2>
      </div>
      <div className="flex items-center gap-1">
        <button className="w-[34px] h-[34px] flex justify-center  items-center bg-[#F4F3EC] border-[0.8px] border-black rounded-full">
          <svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M13.5969 1.99561C11.5857 0.761924 9.8303 1.25908 8.7758 2.05101C8.34335 2.37572 8.1272 2.53807 8 2.53807C7.8728 2.53807 7.65665 2.37572 7.2242 2.05101C6.16971 1.25908 4.41432 0.761924 2.40308 1.99561C-0.236448 3.61471 -0.83371 8.95618 5.25465 13.4626C6.41429 14.3209 6.9941 14.75 8 14.75C9.0059 14.75 9.58572 14.3209 10.7454 13.4626C16.8337 8.95618 16.2364 3.61471 13.5969 1.99561Z"
              stroke="black"
              strokeLinecap="round"
            />
          </svg>
        </button>

        <Link
          href="/cart"
          className="w-[34px] h-[34px] flex justify-center  items-center bg-[#F4F3EC] border-[0.8px] border-black rounded-full"
        >
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M6 12H11.4474C14.8131 12 15.325 9.8856 15.9458 6.80181C16.1249 5.91233 16.2144 5.4676 15.9991 5.1713C15.7838 4.875 15.371 4.875 14.5456 4.875H4.5"
              stroke="black"
              strokeLinecap="round"
            />
            <path
              d="M6 12L4.03405 2.6362C3.86711 1.96844 3.26714 1.5 2.57884 1.5H1.875"
              stroke="black"
              strokeLinecap="round"
            />
            <path
              d="M6.66 12H6.35143C5.32891 12 4.5 12.8635 4.5 13.9285C4.5 14.1061 4.63815 14.25 4.80857 14.25H13.125"
              stroke="black"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M7.875 16.5C8.49632 16.5 9 15.9963 9 15.375C9 14.7537 8.49632 14.25 7.875 14.25C7.25368 14.25 6.75 14.7537 6.75 15.375C6.75 15.9963 7.25368 16.5 7.875 16.5Z"
              stroke="black"
            />
            <path
              d="M13.125 16.5C13.7463 16.5 14.25 15.9963 14.25 15.375C14.25 14.7537 13.7463 14.25 13.125 14.25C12.5037 14.25 12 14.7537 12 15.375C12 15.9963 12.5037 16.5 13.125 16.5Z"
              stroke="black"
            />
          </svg>
        </Link>
      </div>
    </div>
  );
};

export default MobileNavBar;
