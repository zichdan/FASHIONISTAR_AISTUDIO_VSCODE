"use client";
import React, { useState, useEffect } from "react";
import Image from "next/image";
import logo from "../../../../public/logo.svg";
import Link from "next/link";
import { usePathname } from "next/navigation";
import menu from "../../../../public/menu.svg";
import AdminTopBanner from "../../components/AdminTopBanner";

const Layout = ({ children }: { children: React.ReactNode }) => {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const pathname = usePathname();
  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);
  return (
    <div className="flex flex-col">
      <div className="p-[11px] w-full bg-[#F4F3EC]">
        <div className="flex items-center justify-between px-2.5 bg-[#EDE7D9] rounded-[5px] h-[50px] lg:hidden">
          <button
            onClick={() => setIsOpen(true)}
            className="w-[34px] h-[34px] flex justify-center  items-center bg-[#F4F3EC] border-[0.8px] border-black rounded-full"
          >
            <Image src={menu} alt="" />
          </button>
          <div className="flex items-center">
            <Image src={logo} alt="logo" className="w-[39px] h-[38px]" />
            <h2 className="font-bon_foyage px-3 text-[25px] leading-[25px] text-black">
              Fashionistar
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <button className="w-8 h-8 flex justify-center items-center border border-[#282828] rounded-full bg-white">
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
            <button className="w-8 h-8 flex justify-center items-center border border-[#282828] rounded-full bg-white">
              <svg
                width="18"
                height="18"
                viewBox="0 0 18 18"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M1.5 4.5L6.68477 7.43773C8.5962 8.52075 9.4038 8.52075 11.3152 7.43773L16.5 4.5"
                  stroke="#282828"
                  strokeLinejoin="round"
                />
                <path
                  d="M1.51183 10.1067C1.56086 12.4059 1.58537 13.5554 2.43372 14.4071C3.28206 15.2586 4.46275 15.2882 6.82412 15.3476C8.27948 15.3842 9.72053 15.3842 11.1759 15.3476C13.5373 15.2882 14.7179 15.2586 15.5663 14.4071C16.4147 13.5554 16.4392 12.4059 16.4881 10.1067C16.504 9.36743 16.504 8.63258 16.4881 7.8933C16.4392 5.59415 16.4147 4.44457 15.5663 3.593C14.7179 2.74142 13.5373 2.71176 11.1759 2.65243C9.72053 2.61586 8.27947 2.61586 6.82411 2.65242C4.46275 2.71175 3.28206 2.74141 2.43371 3.59299C1.58537 4.44456 1.56085 5.59414 1.51182 7.8933C1.49605 8.63258 1.49606 9.36743 1.51183 10.1067Z"
                  stroke="#282828"
                  strokeLinejoin="round"
                />
              </svg>
            </button>
            <div className="w-[34px] h-[34px] flex justify-center items-center rounded-full bg-[#fda600]">
              <span className="font-medium text-white">G</span>
            </div>
          </div>
        </div>
      </div>

      <div
        className={`w-full lg:left-0 md:w-[40%] lg:w-[25%] z-50 h-screen bg-[#141414] fixed top-0 transition-all duration-300 ${
          isOpen ? "left-0" : "left-[-100%]"
        }`}
      >
        <button
          onClick={() => setIsOpen(false)}
          className=" w-8 h-8 flex justify-center items-center absolute top-2 right-2 md:hidden"
        >
          <svg
            className="text-white "
            width="20"
            height="20"
            viewBox="0 0 20 20"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M15.8334 4.1665L4.16675 15.8332M4.16675 4.1665L15.8334 15.8332"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <div className="flex items-center md:justify-center px-10 py-5 md:py-[30px] border-b-[1.2px] border-b-[#282828]">
          <Image src={logo} alt="logo" className="w-[55px] h-[54px]" />
          <h2 className="font-bon_foyage px-3 text-4xl leading-9 text-white">
            Fashionistar
          </h2>
        </div>

        <nav className="px-10 py-[30px] flex flex-col justify-between h-[86%]">
          <ul className="flex flex-col gap-10">
            <li>
              {" "}
              <Link
                href="/client/dashboard"
                className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                  pathname == "/client/dashboard"
                    ? "text-[#fda600]"
                    : "text-[#bbb]"
                }`}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M16 5C16 4.06812 16 3.60218 16.1522 3.23463C16.3552 2.74458 16.7446 2.35523 17.2346 2.15224C17.6022 2 18.0681 2 19 2C19.9319 2 20.3978 2 20.7654 2.15224C21.2554 2.35523 21.6448 2.74458 21.8478 3.23463C22 3.60218 22 4.06812 22 5V9C22 9.93188 22 10.3978 21.8478 10.7654C21.6448 11.2554 21.2554 11.6448 20.7654 11.8478C20.3978 12 19.9319 12 19 12C18.0681 12 17.6022 12 17.2346 11.8478C16.7446 11.6448 16.3552 11.2554 16.1522 10.7654C16 10.3978 16 9.93188 16 9V5Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M16 19C16 18.0681 16 17.6022 16.1522 17.2346C16.3552 16.7446 16.7446 16.3552 17.2346 16.1522C17.6022 16 18.0681 16 19 16C19.9319 16 20.3978 16 20.7654 16.1522C21.2554 16.3552 21.6448 16.7446 21.8478 17.2346C22 17.6022 22 18.0681 22 19C22 19.9319 22 20.3978 21.8478 20.7654C21.6448 21.2554 21.2554 21.6448 20.7654 21.8478C20.3978 22 19.9319 22 19 22C18.0681 22 17.6022 22 17.2346 21.8478C16.7446 21.6448 16.3552 21.2554 16.1522 20.7654C16 20.3978 16 19.9319 16 19Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M2 16C2 14.1144 2 13.1716 2.58579 12.5858C3.17157 12 4.11438 12 6 12H8C9.88562 12 10.8284 12 11.4142 12.5858C12 13.1716 12 14.1144 12 16V18C12 19.8856 12 20.8284 11.4142 21.4142C10.8284 22 9.88562 22 8 22H6C4.11438 22 3.17157 22 2.58579 21.4142C2 20.8284 2 19.8856 2 18V16Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M2 5C2 4.06812 2 3.60218 2.15224 3.23463C2.35523 2.74458 2.74458 2.35523 3.23463 2.15224C3.60218 2 4.06812 2 5 2H9C9.93188 2 10.3978 2 10.7654 2.15224C11.2554 2.35523 11.6448 2.74458 11.8478 3.23463C12 3.60218 12 4.06812 12 5C12 5.93188 12 6.39782 11.8478 6.76537C11.6448 7.25542 11.2554 7.64477 10.7654 7.84776C10.3978 8 9.93188 8 9 8H5C4.06812 8 3.60218 8 3.23463 7.84776C2.74458 7.64477 2.35523 7.25542 2.15224 6.76537C2 6.39782 2 5.93188 2 5Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                </svg>
                Dashboard
              </Link>
            </li>
            <li>
              <Link
                href="/client/dashboard/orders"
                className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                  pathname == "/client/dashboard/orders"
                    ? "text-[#fda600]"
                    : "text-[#bbb]"
                }`}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M16.365 2.86816V4.78057M11.584 2.86816V4.78057M6.80298 2.86816V4.78057"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M3.4563 13.3863V9.56144C3.4563 6.85689 3.4563 5.50461 4.2965 4.66442C5.13669 3.82422 6.48897 3.82422 9.19352 3.82422H13.9745C16.6791 3.82422 18.0313 3.82422 18.8716 4.66442C19.7118 5.50461 19.7118 6.85689 19.7118 9.56144V13.3863C19.7118 16.0908 19.7118 17.4431 18.8716 18.2833C18.0313 19.1235 16.6791 19.1235 13.9745 19.1235H9.19352C6.48897 19.1235 5.13669 19.1235 4.2965 18.2833C3.4563 17.4431 3.4563 16.0908 3.4563 13.3863Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M3.4563 16.2549V9.56144C3.4563 6.85689 3.4563 5.50461 4.2965 4.66442C5.13669 3.82422 6.48897 3.82422 9.19352 3.82422H13.9745C16.6791 3.82422 18.0313 3.82422 18.8716 4.66442C19.7118 5.50461 19.7118 6.85689 19.7118 9.56144V16.2549C19.7118 18.9594 19.7118 20.3117 18.8716 21.1519C18.0313 21.9921 16.6791 21.9921 13.9745 21.9921H9.19352C6.48897 21.9921 5.13669 21.9921 4.2965 21.1519C3.4563 20.3117 3.4563 18.9594 3.4563 16.2549Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M7.75903 15.2996H11.5839M7.75903 10.5186H15.4087"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                </svg>
                Orders
              </Link>
              <ul
                className={`pl-4 pt-10 ${
                  pathname.includes("/client/dashboard/orders")
                    ? "inline-flex"
                    : "hidden"
                } `}
              >
                <li>
                  <Link
                    href="/client/dashboard/orders/track-order"
                    className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                      pathname == "/client/dashboard/orders/track-order"
                        ? "text-[#fda600]"
                        : "text-[#bbb]"
                    }`}
                  >
                    <svg
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        d="M4.4126 10.7719V6.69336H18.7557V10.7719C18.7557 13.8076 18.7557 15.3255 17.8221 16.2685C16.8886 17.2116 15.386 17.2116 12.3809 17.2116H10.7873C7.78223 17.2116 6.2797 17.2116 5.34615 16.2685C4.4126 15.3255 4.4126 13.8076 4.4126 10.7719Z"
                        stroke="currentColor"
                        stroke-width="1.43431"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      />
                      <path
                        d="M4.4126 6.69396L5.10216 5.22288C5.63697 4.08197 5.90436 3.51152 6.44637 3.19033C6.98837 2.86914 7.68362 2.86914 9.07409 2.86914H14.0942C15.4847 2.86914 16.1798 2.86914 16.7219 3.19033C17.2639 3.51152 17.5313 4.08197 18.066 5.22288L18.7557 6.69396"
                        stroke="currentColor"
                        stroke-width="1.43431"
                        stroke-linecap="round"
                      />
                      <path
                        d="M10.1494 9.5625H13.018"
                        stroke="currentColor"
                        stroke-width="1.43431"
                        stroke-linecap="round"
                      />
                      <path
                        d="M11.584 19.6035V21.994M11.584 19.6035H6.80299M11.584 19.6035H16.365M6.80299 19.6035H4.41248C3.09224 19.6035 2.02197 20.6738 2.02197 21.994M6.80299 19.6035V21.994M16.365 19.6035H18.7555C20.0758 19.6035 21.1461 20.6738 21.1461 21.994M16.365 19.6035V21.994"
                        stroke="currentColor"
                        stroke-width="1.43431"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      />
                    </svg>
                    Track my Order
                  </Link>
                </li>
              </ul>
            </li>

            <li>
              {" "}
              <Link
                href="/client/dashboard/address"
                className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                  pathname == "/client/dashboard/address"
                    ? "text-[#fda600]"
                    : "text-[#bbb]"
                }`}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M6.80298 17.1676V13.3428"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                  <path
                    d="M11.584 17.1675V7.60547"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                  <path
                    d="M16.365 17.1679V11.4307"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                  <path
                    d="M2.5 12.3867C2.5 8.10447 2.5 5.96336 3.83031 4.63304C5.16063 3.30273 7.30173 3.30273 11.5839 3.30273C15.8661 3.30273 18.0072 3.30273 19.3376 4.63304C20.6679 5.96336 20.6679 8.10447 20.6679 12.3867C20.6679 16.6688 20.6679 18.81 19.3376 20.1403C18.0072 21.4706 15.8661 21.4706 11.5839 21.4706C7.30173 21.4706 5.16063 21.4706 3.83031 20.1403C2.5 18.81 2.5 16.6688 2.5 12.3867Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinejoin="round"
                  />
                </svg>
                My Address
              </Link>
            </li>

            <li>
              <Link
                href="/client/dashboard/account-details"
                className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                  pathname.includes("/account-details")
                    ? "text-[#fda600]"
                    : "text-[#bbb]"
                }`}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M14.4526 8.12725C14.4526 8.12725 14.9307 8.12725 15.4088 9.08346C15.4088 9.08346 16.9275 6.69295 18.2775 6.21484"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M21.146 7.64919C21.146 10.2897 19.0055 12.4302 16.365 12.4302C13.7245 12.4302 11.584 10.2897 11.584 7.64919C11.584 5.0087 13.7245 2.86816 16.365 2.86816C19.0055 2.86816 21.146 5.0087 21.146 7.64919Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                  <path
                    d="M21.8631 13.6201C21.8624 13.2239 21.5407 12.9034 21.1447 12.9042C20.7486 12.9049 20.4281 13.2265 20.4288 13.6226L21.8631 13.6201ZM8.77821 7.41281C9.17428 7.41057 9.49354 7.08768 9.4913 6.69162C9.48905 6.29555 9.16616 5.97629 8.7701 5.97853L8.77821 7.41281ZM13.0182 21.2754H10.1496V22.7097H13.0182V21.2754ZM10.1496 21.2754C8.33576 21.2754 7.03573 21.2743 6.0369 21.1615C5.05125 21.0501 4.45403 20.8381 4.00337 20.4822L3.11443 21.6078C3.86349 22.1994 4.76464 22.4612 5.8759 22.5867C6.97399 22.7107 8.36943 22.7097 10.1496 22.7097V21.2754ZM1.30469 14.3429C1.30469 16.0152 1.30332 17.3374 1.43628 18.3802C1.57178 19.4426 1.85624 20.3086 2.49323 21.0231L3.56384 20.0686C3.19414 19.6539 2.97525 19.1098 2.85907 18.1987C2.74036 17.2678 2.73899 16.0532 2.73899 14.3429H1.30469ZM4.00337 20.4822C3.84384 20.3563 3.69682 20.2178 3.56384 20.0686L2.49323 21.0231C2.68227 21.2352 2.89018 21.4308 3.11443 21.6078L4.00337 20.4822ZM20.4288 14.3429C20.4288 16.0532 20.4274 17.2678 20.3087 18.1987C20.1925 19.1098 19.9736 19.6539 19.604 20.0686L20.6745 21.0231C21.3115 20.3086 21.596 19.4426 21.7315 18.3802C21.8644 17.3374 21.8631 16.0152 21.8631 14.3429H20.4288ZM13.0182 22.7097C14.7984 22.7097 16.1937 22.7107 17.2919 22.5867C18.4032 22.4612 19.3043 22.1994 20.0534 21.6078L19.1644 20.4822C18.7137 20.8381 18.1165 21.0501 17.1308 21.1615C16.1321 21.2743 14.832 21.2754 13.0182 21.2754V22.7097ZM19.604 20.0686C19.4709 20.2178 19.324 20.3563 19.1644 20.4822L20.0534 21.6078C20.2776 21.4308 20.4855 21.2352 20.6745 21.0231L19.604 20.0686ZM2.73899 14.3429C2.73899 12.6326 2.74036 11.418 2.85907 10.4871C2.97525 9.57601 3.19414 9.0318 3.56384 8.61713L2.49323 7.66265C1.85624 8.37714 1.57178 9.24315 1.43628 10.3056C1.30332 11.3483 1.30469 12.6706 1.30469 14.3429H2.73899ZM3.11443 7.07791C2.89018 7.25501 2.68227 7.45061 2.49323 7.66265L3.56384 8.61713C3.69682 8.46797 3.84384 8.32952 4.00337 8.20354L3.11443 7.07791ZM21.8631 14.3429C21.8631 14.095 21.8635 13.8524 21.8631 13.6201L20.4288 13.6226C20.4292 13.8534 20.4288 14.0916 20.4288 14.3429H21.8631ZM8.7701 5.97853C7.42419 5.98615 6.32869 6.01715 5.43126 6.15877C4.52041 6.30253 3.76081 6.56743 3.11443 7.07791L4.00337 8.20354C4.39281 7.89598 4.89164 7.69599 5.65486 7.57555C6.43151 7.45298 7.42572 7.42046 8.77821 7.41281L8.7701 5.97853Z"
                    fill="currentColor"
                  />
                  <path
                    d="M9.67163 18.168H11.1059"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeMiterlimit="10"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M13.9744 18.168H17.3211"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeMiterlimit="10"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M2.5 11.4746H9.67153"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                Account Details
              </Link>
            </li>

            <li>
              <Link
                href="/client/dashboard/wallet"
                className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 ${
                  pathname.includes("/wallet")
                    ? "text-[#fda600]"
                    : "text-[#bbb]"
                }`}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M17.9103 20.0804H18.379C19.4785 20.0804 20.353 19.5794 21.1382 18.879C23.133 17.0995 18.4439 15.2993 16.8431 15.2993M14.9307 5.80306C15.1478 5.76 15.3733 5.7373 15.6046 5.7373C17.3448 5.7373 18.7555 7.02163 18.7555 8.60592C18.7555 10.1902 17.3448 11.4745 15.6046 11.4745C15.3733 11.4745 15.1478 11.4519 14.9307 11.4087"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                  <path
                    d="M4.39444 16.3614C3.26711 16.9655 0.311286 18.1991 2.11157 19.7427C2.991 20.4968 3.97046 21.0361 5.20187 21.0361H12.2286C13.46 21.0361 14.4395 20.4968 15.3189 19.7427C17.1192 18.1991 14.1634 16.9655 13.036 16.3614C10.3924 14.9447 7.03804 14.9447 4.39444 16.3614Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M12.5403 8.12755C12.5403 10.2399 10.8278 11.9524 8.71544 11.9524C6.60305 11.9524 4.89062 10.2399 4.89062 8.12755C4.89062 6.01516 6.60305 4.30273 8.71544 4.30273C10.8278 4.30273 12.5403 6.01516 12.5403 8.12755Z"
                    stroke="currentColor"
                    strokeWidth="1.43431"
                  />
                </svg>
                Wallet
              </Link>
            </li>
          </ul>

          <button
            className={`text-xl leading-[27px] font-medium font-satoshi  flex items-center gap-4 text-[#fff]`}
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M21.3175 7.14139L20.8239 6.28479C20.4506 5.63696 20.264 5.31305 19.9464 5.18388C19.6288 5.05472 19.2696 5.15664 18.5513 5.36048L17.3311 5.70418C16.8725 5.80994 16.3913 5.74994 15.9726 5.53479L15.6357 5.34042C15.2766 5.11043 15.0004 4.77133 14.8475 4.37274L14.5136 3.37536C14.294 2.71534 14.1842 2.38533 13.9228 2.19657C13.6615 2.00781 13.3143 2.00781 12.6199 2.00781H11.5051C10.8108 2.00781 10.4636 2.00781 10.2022 2.19657C9.94085 2.38533 9.83106 2.71534 9.61149 3.37536L9.27753 4.37274C9.12465 4.77133 8.84845 5.11043 8.48937 5.34042L8.15249 5.53479C7.73374 5.74994 7.25259 5.80994 6.79398 5.70418L5.57375 5.36048C4.85541 5.15664 4.49625 5.05472 4.17867 5.18388C3.86109 5.31305 3.67445 5.63696 3.30115 6.28479L2.80757 7.14139C2.45766 7.74864 2.2827 8.05227 2.31666 8.37549C2.35061 8.69871 2.58483 8.95918 3.05326 9.48012L4.0843 10.6328C4.3363 10.9518 4.51521 11.5078 4.51521 12.0077C4.51521 12.5078 4.33636 13.0636 4.08433 13.3827L3.05326 14.5354C2.58483 15.0564 2.35062 15.3168 2.31666 15.6401C2.2827 15.9633 2.45766 16.2669 2.80757 16.8741L3.30114 17.7307C3.67443 18.3785 3.86109 18.7025 4.17867 18.8316C4.49625 18.9608 4.85542 18.8589 5.57377 18.655L6.79394 18.3113C7.25263 18.2055 7.73387 18.2656 8.15267 18.4808L8.4895 18.6752C8.84851 18.9052 9.12464 19.2442 9.2775 19.6428L9.61149 20.6403C9.83106 21.3003 9.94085 21.6303 10.2022 21.8191C10.4636 22.0078 10.8108 22.0078 11.5051 22.0078H12.6199C13.3143 22.0078 13.6615 22.0078 13.9228 21.8191C14.1842 21.6303 14.294 21.3003 14.5136 20.6403L14.8476 19.6428C15.0004 19.2442 15.2765 18.9052 15.6356 18.6752L15.9724 18.4808C16.3912 18.2656 16.8724 18.2055 17.3311 18.3113L18.5513 18.655C19.2696 18.8589 19.6288 18.9608 19.9464 18.8316C20.264 18.7025 20.4506 18.3785 20.8239 17.7307L21.3175 16.8741C21.6674 16.2669 21.8423 15.9633 21.8084 15.6401C21.7744 15.3168 21.5402 15.0564 21.0718 14.5354L20.0407 13.3827C19.7887 13.0636 19.6098 12.5078 19.6098 12.0077C19.6098 11.5078 19.7888 10.9518 20.0407 10.6328L21.0718 9.48012C21.5402 8.95918 21.7744 8.69871 21.8084 8.37549C21.8423 8.05227 21.6674 7.74864 21.3175 7.14139Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <path
                d="M15.5195 12C15.5195 13.933 13.9525 15.5 12.0195 15.5C10.0865 15.5 8.51953 13.933 8.51953 12C8.51953 10.067 10.0865 8.5 12.0195 8.5C13.9525 8.5 15.5195 10.067 15.5195 12Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
            Logout
          </button>
        </nav>
      </div>
      <div className="lg:ml-[25%] bg-[#F4F3EC] min-h-screen flex flex-col">
        <AdminTopBanner title="Jennifer" pathname={pathname} />
        <div className="p-3 md:p-[30px] mt-1 lg:mt-[100px] bg-inherit space-y-10">
          {children}
        </div>
      </div>
    </div>
  );
};

export default Layout;
