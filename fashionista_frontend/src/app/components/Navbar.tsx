"use client";
import React from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";

const Navbar = () => {
  const pathname = usePathname();

  return (
    <nav className="flex justify-evenly bg-[#fda600] px-2 lg:px-4 md:py-5 lg:py-2 font-satoshi sticky top-0 z-50 ">
      <Link
        href="/"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/" ? "text-white font-bold" : "text-black font-medium "
        } `}
      >
        Home
      </Link>
      <Link
        href="/about-us"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/about-us"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        About
      </Link>
      <Link
        href="/categories"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/categories"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Categories
      </Link>
      <Link
        href="/vendor"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/vendor"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Vendors
      </Link>
      <Link
        href="/shops"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/shops"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Shops
      </Link>
      <Link
        href="/collections"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/collections"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Collections
      </Link>
      <Link
        href="/testimonails"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/testimonails"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Testimonials
      </Link>
      <Link
        href="/contact-us"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/contact-us"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Contact Us
      </Link>
      <Link
        href="/shops"
        className={`text-lg leading-6  hover:text-white ${
          pathname === "/blog"
            ? "text-white font-bold"
            : "text-black font-medium "
        } `}
      >
        Blog
      </Link>

      <div className="hidden lg:flex flex-col">
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
          <span className="font-medium md:text-sm lg:text-xl px-2 leading-[27px] text-black w-[127px]">
            +234 90 0000 000
          </span>
        </div>

        <div className="flex justify-end ">
          <span className="text-black pr-2 leading-4 text-xs font-medium ">
            24/7 support center
          </span>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
