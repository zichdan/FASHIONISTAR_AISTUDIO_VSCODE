"use client";
import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import logo from "../../../public/logo.svg";
import Image from "next/image";
import AccountOptions from "./AccountOptions";
import CartItems from "./CartItems";
import {
  Search,
  AlignJustify,
  UserRound,
  ShoppingCart,
  X,
  Headset,
  CircleAlert,
  MapPin,
  MessageSquareText,
  UserRoundPlus,
} from "lucide-react";
import Link from "next/link";

const NewMobileNav = () => {
  const pathname = usePathname();
  const [showNav, setShowNav] = useState<boolean>(false);
  const [showOptions, setShowOptions] = useState<boolean>(false);
  const [isOpen, setIsOpen] = useState(false);
  useEffect(() => {
    setShowNav(false);
  }, [pathname]);
  return (
    <div
      style={{
        boxShadow: "0px 4px 25px 0px #0000001A",
      }}
      className="flex justify-between items-center bg-white md:hidden p-6"
    >
      <div className="flex items-center gap-2 w-1/2 ">
        <Image src={logo} alt="Fashionistar Logo" className="w-10 h-10 " />
        <h2 className="font-bon_foyage text-2xl text-[#333]">Fashionistar</h2>
      </div>
      <div className="flex items-center space-x-2 md:space-x-4">
        <button onClick={() => setShowNav(true)} className=" ">
          <AlignJustify />
        </button>
        <button className="">
          <Search />
        </button>
        <div className="relative">
          <button type="button" onClick={() => setShowOptions((prev) => !prev)}>
            <UserRound />
          </button>
          <AccountOptions showOptions={showOptions} />
        </div>

        <div className="relative flex">
          <button onClick={() => setIsOpen(true)} className="">
            <ShoppingCart />
          </button>
          <sub className="bg-[#fda600] absolute -top-3 -right-3 font-bold flex justify-center items-center w-5 h-5 rounded-full">
            0
          </sub>
          <CartItems isOpen={isOpen} onClose={() => setIsOpen(false)} />
        </div>
      </div>
      <div
        tabIndex={100}
        className={`fixed top-0 w-full transition-all ease-in-out duration-150  flex flex-col h-screen min-h-screen bg-[#fff] z-50 ${
          showNav ? "left-0" : "-left-[100%]"
        }`}
      >
        <div className="bg-[#01454A] py-5 px-6 flex items-center justify-between">
          <div className="flex items-center gap-2 w-1/2 ">
            <Image src={logo} alt="Fashionistar Logo" className="w-10 h-10 " />
            <h2 className="font-bon_foyage text-2xl text-[#fff]">
              Fashionistar
            </h2>
          </div>
          <button onClick={() => setShowNav(false)}>
            <X color="#fff" />
          </button>
        </div>
        <div className="bg-[#fff] px-6 py-5 flex flex-col justify-between  gap-4">
          <nav>
            <Link
              href="/"
              className={`w-full py-3 px-4 border-b border-[#BBBBBB] flex items-center gap-3 font-medium text-lg font-raleway ${
                pathname == "/"
                  ? "bg-[#fda600]/80 text-white"
                  : "bg-white text-[#141414]"
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
                  d="M9.02 2.84001L3.63 7.04001C2.73 7.74001 2 9.23001 2 10.36V17.77C2 20.09 3.89 21.99 6.21 21.99H17.79C20.11 21.99 22 20.09 22 17.78V10.5C22 9.29001 21.19 7.74001 20.2 7.05001L14.02 2.72001C12.62 1.74001 10.37 1.79001 9.02 2.84001Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M12 17.99V14.99"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              Home
            </Link>
            <Link
              href="/categories"
              className={`w-full py-3 border-b border-[#BBBBBB] px-4 flex items-center gap-3 font-medium text-lg font-raleway ${
                pathname == "/categories"
                  ? "bg-[#fda600] text-white"
                  : "bg-white text-[#141414]"
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
                  d="M10.5 19.9V4.1C10.5 2.6 9.86 2 8.27 2H4.23C2.64 2 2 2.6 2 4.1V19.9C2 21.4 2.64 22 4.23 22H8.27C9.86 22 10.5 21.4 10.5 19.9Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M22 12.9V4.1C22 2.6 21.36 2 19.77 2H15.73C14.14 2 13.5 2.6 13.5 4.1V12.9C13.5 14.4 14.14 15 15.73 15H19.77C21.36 15 22 14.4 22 12.9Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              Categories
            </Link>
            <Link
              href="/vendors"
              className={`w-full py-3 border-b border-[#BBBBBB] px-4 flex items-center gap-3 font-medium text-lg font-raleway ${
                pathname == "/vendors"
                  ? "bg-[#fda600] text-white"
                  : "bg-white text-[#141414]"
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
                  d="M3.01001 11.22V15.71C3.01001 20.2 4.81001 22 9.30001 22H14.69C19.18 22 20.98 20.2 20.98 15.71V11.22"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M12 12C13.83 12 15.18 10.51 15 8.68L14.34 2H9.66999L8.99999 8.68C8.81999 10.51 10.17 12 12 12Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M18.31 12C20.33 12 21.81 10.36 21.61 8.35L21.33 5.6C20.97 3 19.97 2 17.35 2H14.3L15 9.01C15.17 10.66 16.66 12 18.31 12Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M5.63988 12C7.28988 12 8.77988 10.66 8.93988 9.01L9.15988 6.8L9.63988 2H6.58988C3.96988 2 2.96988 3 2.60988 5.6L2.33988 8.35C2.13988 10.36 3.61988 12 5.63988 12Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M12 17C10.33 17 9.5 17.83 9.5 19.5V22H14.5V19.5C14.5 17.83 13.67 17 12 17Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              Vendors
            </Link>
            <Link
              href="/shop"
              className={`w-full py-3 border-b border-[#BBBBBB] px-4 flex items-center gap-3 font-medium text-lg font-raleway ${
                pathname == "/shop"
                  ? "bg-[#fda600] text-white"
                  : "bg-white text-[#141414]"
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
                  d="M8.5 14.25C8.5 16.17 10.08 17.75 12 17.75C13.92 17.75 15.5 16.17 15.5 14.25"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M8.80994 2L5.18994 5.63"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M15.1899 2L18.8099 5.63"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M2 7.85001C2 6.00001 2.99 5.85001 4.22 5.85001H19.78C21.01 5.85001 22 6.00001 22 7.85001C22 10 21.01 9.85001 19.78 9.85001H4.22C2.99 9.85001 2 10 2 7.85001Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                />
                <path
                  d="M3.5 10L4.91 18.64C5.23 20.58 6 22 8.86 22H14.89C18 22 18.46 20.64 18.82 18.76L20.5 10"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                />
              </svg>
              Shop
            </Link>
            <Link
              href="/collections"
              className={`w-full py-3 border-b border-[#BBBBBB] px-4 flex items-center gap-3 font-medium text-lg font-raleway ${
                pathname == "/collections"
                  ? "bg-[#fda600] text-white"
                  : "bg-white text-[#141414]"
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
                  d="M7.5 7.67001V6.70001C7.5 4.45001 9.31 2.24001 11.56 2.03001C14.24 1.77001 16.5 3.88001 16.5 6.51001V7.89001"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M9.00007 22H15.0001C19.0201 22 19.7401 20.39 19.9501 18.43L20.7001 12.43C20.9701 9.99 20.2701 8 16.0001 8H8.00007C3.73007 8 3.03007 9.99 3.30007 12.43L4.05007 18.43C4.26007 20.39 4.98007 22 9.00007 22Z"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M15.4955 12H15.5045"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M8.49451 12H8.50349"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              Collections
            </Link>
          </nav>
          <div className="bg-[#F4F5FB]/10 rounded-xl border border-[#F4F5FB] py-5 px-3 space-y-5">
            <div className="flex items-center justify-between border-b border-[#BBBBBB] py-2 px-2">
              <Link
                href="/"
                className="font-raleway font-medium text-lg text-[#141414] flex items-center gap-2 border-r w-1/2 border-[#BBB]"
              >
                <Headset />
                Support
              </Link>

              <Link
                href="/about-us"
                className="flex items-center gap-2 font-raleway font-medium text-lg text-[#141414]"
              >
                <CircleAlert />
                About Us
              </Link>
            </div>
            <div className="flex items-center justify-between border-b border-[#BBBBBB] py-2 px-2">
              <Link
                href="/"
                className="font-raleway font-medium text-lg text-[#141414] flex items-center gap-2 border-r w-1/2 border-[#BBB]"
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M16 2H8C4 2 2 4 2 8V21C2 21.55 2.45 22 3 22H16C20 22 22 20 22 16V8C22 4 20 2 16 2Z"
                    stroke="#141414"
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  />
                  <path
                    d="M7 9.5H17"
                    stroke="#141414"
                    stroke-width="1.5"
                    stroke-miterlimit="10"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  />
                  <path
                    d="M7 14.5H14"
                    stroke="#141414"
                    stroke-width="1.5"
                    stroke-miterlimit="10"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  />
                </svg>
                Blog
              </Link>

              <Link
                href="/about-us"
                className="flex items-center gap-2 font-raleway font-medium text-lg text-[#141414]"
              >
                <MessageSquareText />
                Pages
              </Link>
            </div>
            <Link
              href="/location"
              className="flex items-center gap-2 font-raleway font-medium text-lg text-[#141414]"
            >
              <MapPin /> Our Location
            </Link>
            <div className="flex items-center justify-between">
              <Link
                href="/login"
                className="flex items-center gap-2 font-raleway font-medium text-lg text-[#141414]"
              >
                <UserRound /> Login/Signup
              </Link>
              <UserRoundPlus />
            </div>
          </div>
          <div className="space-y-2">
            <p className="font-raleway font-medium text-lg text-black">
              Follow us
            </p>
            <div className="flex items-center gap-2">
              <a
                href="/"
                className="w-10 h-10 rounded-full bg-[#fda600] flex justify-center items-center"
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M11.9998 0C5.37253 0 0 5.39238 0 12.0441C0 17.6923 3.87448 22.4319 9.1011 23.7336V15.7248H6.62675V12.0441H9.1011V10.4581C9.1011 6.35879 10.9495 4.45872 14.9594 4.45872C15.7197 4.45872 17.0315 4.60855 17.5681 4.75789V8.0941C17.2849 8.06423 16.7929 8.0493 16.1819 8.0493C14.2144 8.0493 13.4541 8.79748 13.4541 10.7424V12.0441H17.3737L16.7003 15.7248H13.4541V24C19.3959 23.2798 24 18.202 24 12.0441C23.9995 5.39238 18.627 0 11.9998 0Z"
                    fill="white"
                  />
                </svg>
              </a>
              <a
                href="/"
                className="w-10 h-10 rounded-full bg-[#fda600] flex justify-center items-center"
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M18.9014 0H22.5816L14.5415 10.1662L24 24H16.5941L10.7935 15.6098L4.15631 24H0.473926L9.07356 13.1262L0 0H7.59394L12.8372 7.66892L18.9014 0ZM17.6098 21.5631H19.649L6.48589 2.30892H4.29759L17.6098 21.5631Z"
                    fill="white"
                  />
                </svg>
              </a>
              <a
                href="/"
                className="w-10 h-10 rounded-full bg-[#fda600] flex justify-center items-center"
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <g clip-path="url(#clip0_2369_3530)">
                    <path
                      d="M12 2.16094C15.2063 2.16094 15.5859 2.175 16.8469 2.23125C18.0188 2.28281 18.6516 2.47969 19.0734 2.64375C19.6313 2.85938 20.0344 3.12188 20.4516 3.53906C20.8734 3.96094 21.1313 4.35938 21.3469 4.91719C21.5109 5.33906 21.7078 5.97656 21.7594 7.14375C21.8156 8.40937 21.8297 8.78906 21.8297 11.9906C21.8297 15.1969 21.8156 15.5766 21.7594 16.8375C21.7078 18.0094 21.5109 18.6422 21.3469 19.0641C21.1313 19.6219 20.8687 20.025 20.4516 20.4422C20.0297 20.8641 19.6313 21.1219 19.0734 21.3375C18.6516 21.5016 18.0141 21.6984 16.8469 21.75C15.5813 21.8062 15.2016 21.8203 12 21.8203C8.79375 21.8203 8.41406 21.8062 7.15313 21.75C5.98125 21.6984 5.34844 21.5016 4.92656 21.3375C4.36875 21.1219 3.96563 20.8594 3.54844 20.4422C3.12656 20.0203 2.86875 19.6219 2.65313 19.0641C2.48906 18.6422 2.29219 18.0047 2.24063 16.8375C2.18438 15.5719 2.17031 15.1922 2.17031 11.9906C2.17031 8.78438 2.18438 8.40469 2.24063 7.14375C2.29219 5.97187 2.48906 5.33906 2.65313 4.91719C2.86875 4.35938 3.13125 3.95625 3.54844 3.53906C3.97031 3.11719 4.36875 2.85938 4.92656 2.64375C5.34844 2.47969 5.98594 2.28281 7.15313 2.23125C8.41406 2.175 8.79375 2.16094 12 2.16094ZM12 0C8.74219 0 8.33438 0.0140625 7.05469 0.0703125C5.77969 0.126563 4.90313 0.332812 4.14375 0.628125C3.35156 0.9375 2.68125 1.34531 2.01563 2.01562C1.34531 2.68125 0.9375 3.35156 0.628125 4.13906C0.332812 4.90313 0.126563 5.775 0.0703125 7.05C0.0140625 8.33437 0 8.74219 0 12C0 15.2578 0.0140625 15.6656 0.0703125 16.9453C0.126563 18.2203 0.332812 19.0969 0.628125 19.8563C0.9375 20.6484 1.34531 21.3188 2.01563 21.9844C2.68125 22.65 3.35156 23.0625 4.13906 23.3672C4.90313 23.6625 5.775 23.8687 7.05 23.925C8.32969 23.9812 8.7375 23.9953 11.9953 23.9953C15.2531 23.9953 15.6609 23.9812 16.9406 23.925C18.2156 23.8687 19.0922 23.6625 19.8516 23.3672C20.6391 23.0625 21.3094 22.65 21.975 21.9844C22.6406 21.3188 23.0531 20.6484 23.3578 19.8609C23.6531 19.0969 23.8594 18.225 23.9156 16.95C23.9719 15.6703 23.9859 15.2625 23.9859 12.0047C23.9859 8.74688 23.9719 8.33906 23.9156 7.05938C23.8594 5.78438 23.6531 4.90781 23.3578 4.14844C23.0625 3.35156 22.6547 2.68125 21.9844 2.01562C21.3188 1.35 20.6484 0.9375 19.8609 0.632812C19.0969 0.3375 18.225 0.13125 16.95 0.075C15.6656 0.0140625 15.2578 0 12 0Z"
                      fill="white"
                    />
                    <path
                      d="M12 5.83594C8.59688 5.83594 5.83594 8.59688 5.83594 12C5.83594 15.4031 8.59688 18.1641 12 18.1641C15.4031 18.1641 18.1641 15.4031 18.1641 12C18.1641 8.59688 15.4031 5.83594 12 5.83594ZM12 15.9984C9.79219 15.9984 8.00156 14.2078 8.00156 12C8.00156 9.79219 9.79219 8.00156 12 8.00156C14.2078 8.00156 15.9984 9.79219 15.9984 12C15.9984 14.2078 14.2078 15.9984 12 15.9984Z"
                      fill="white"
                    />
                    <path
                      d="M19.8469 5.59214C19.8469 6.38902 19.2 7.0312 18.4078 7.0312C17.6109 7.0312 16.9688 6.38433 16.9688 5.59214C16.9688 4.79526 17.6156 4.15308 18.4078 4.15308C19.2 4.15308 19.8469 4.79995 19.8469 5.59214Z"
                      fill="white"
                    />
                  </g>
                  <defs>
                    <clipPath id="clip0_2369_3530">
                      <rect width="24" height="24" fill="white" />
                    </clipPath>
                  </defs>
                </svg>
              </a>
              <a
                href="/"
                className="w-10 h-10 rounded-full bg-[#fda600] flex justify-center items-center"
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M17.6459 0H12.9106V16.3478C12.9106 18.2957 11.0894 19.8957 8.82294 19.8957C6.55649 19.8957 4.73525 18.2957 4.73525 16.3478C4.73525 14.4348 6.51602 12.8695 8.70155 12.8V8.69567C3.88533 8.7652 0 12.1391 0 16.3478C0 20.5913 3.96627 24 8.86343 24C13.7605 24 17.7268 20.5565 17.7268 16.3478V7.9652C19.5076 9.07827 21.6931 9.73913 24 9.77393V5.66957C20.4385 5.56522 17.6459 3.06087 17.6459 0Z"
                    fill="white"
                  />
                </svg>
              </a>
              <a
                href="/"
                className="w-10 h-10 rounded-full bg-[#fda600] flex justify-center items-center"
              >
                <svg
                  width="26"
                  height="24"
                  viewBox="0 0 26 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M25.741 5.17856C25.741 5.17856 25.4871 2.82588 24.7051 1.79284C23.7148 0.433213 22.6078 0.426548 22.1 0.34657C18.4641 -1.90682e-07 13.0051 0 13.0051 0H12.9949C12.9949 0 7.53594 -1.90682e-07 3.9 0.34657C3.39219 0.426548 2.28516 0.433213 1.29492 1.79284C0.512891 2.82588 0.264062 5.17856 0.264062 5.17856C0.264062 5.17856 0 7.94446 0 10.7037V13.2896C0 16.0489 0.258984 18.8148 0.258984 18.8148C0.258984 18.8148 0.512891 21.1675 1.28984 22.2005C2.28008 23.5601 3.58008 23.5135 4.15898 23.6601C6.24102 23.92 13 24 13 24C13 24 18.4641 23.9867 22.1 23.6468C22.6078 23.5668 23.7148 23.5601 24.7051 22.2005C25.4871 21.1675 25.741 18.8148 25.741 18.8148C25.741 18.8148 26 16.0555 26 13.2896V10.7037C26 7.94446 25.741 5.17856 25.741 5.17856ZM10.3137 16.4288V6.8381L17.3367 11.6501L10.3137 16.4288Z"
                    fill="white"
                  />
                </svg>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NewMobileNav;
