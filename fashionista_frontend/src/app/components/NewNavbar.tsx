"use client";
import React, { useState } from "react";
import { Search, UserRound, ShoppingCart } from "lucide-react";
import logo from "../../../public/logo.svg";
import { usePathname } from "next/navigation";
import Image from "next/image";
import Link from "next/link";
import AccountOptions from "./AccountOptions";
import CartItems from "./CartItems";

const NewNavbar = () => {
  const [showOptions, setShowOptions] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [showCart, setShowCart] = useState(false);
  const pathname = usePathname();
  return (
    <div
      className="hidden md:flex md:flex-wrap lg:flex-nowrap justify-between bg-white items-center py-5 px-2 lg:px-20 sticky top-0 z-40 "
      style={{
        boxShadow: "0px 4px 25px 0px #0000001A",
      }}
    >
      <div className="flex items-center gap-2 w-1/2 md:w-full lg:w-fit">
        <Image
          src={logo}
          alt="Fashionistar Logo"
          className="w-10 h-10 md:w-[55px] md:h-[56px]"
        />
        <h2 className="font-bon_foyage text-2xl md:text-4xl text-[#333]">
          Fashionistar
        </h2>
      </div>

      <nav className="flex items-center justify-between  w-1/2">
        <ul className="flex w-full items-center justify-between">
          <li className="flex grow-0 order-1 flex-none ">
            <Link
              href="/"
              className={`font-raleway text-lg text-[#333] hover:text-[#fda600] ${
                pathname == "/"
                  ? "font-bold text-[#fda600]"
                  : "font-medium text-[#333]"
              } grow-0`}
            >
              Home
            </Link>
          </li>
          <li className="flex grow-0 order-1 flex-none  ">
            <Link
              href="/categories"
              className={`font-raleway text-lg text-[#333] hover:text-[#fda600] ${
                pathname == "/category"
                  ? "font-bold text-[#fda600]"
                  : "font-medium text-[#333]"
              } grow-0`}
            >
              Categories
            </Link>
          </li>
          <li className="flex grow-0 order-1 flex-none  ">
            <Link
              href="/vendors"
              className={`font-raleway text-lg text-[#333] hover:text-[#fda600] ${
                pathname == "/vendors"
                  ? "font-bold text-[#fda600]"
                  : "font-medium text-[#333]"
              } grow-0`}
            >
              Vendors
            </Link>
          </li>
          <li className="flex grow-0 order-1 flex-none  ">
            <Link
              href="/shops"
              className={`font-raleway text-lg text-[#333] hover:text-[#fda600] ${
                pathname == "/shops"
                  ? "font-bold text-[#fda600]"
                  : "font-medium text-[#333]"
              } grow-0`}
            >
              Shop
            </Link>
          </li>
          <li className="flex grow-0 order-1 flex-none  ">
            <Link
              href="/collections"
              className={`font-raleway text-lg text-[#333] hover:text-[#fda600] ${
                pathname == "/collections"
                  ? "font-bold text-[#fda600]"
                  : "font-medium text-[#333]"
              } grow-0`}
            >
              Collections
            </Link>
          </li>
        </ul>
      </nav>
      <div className="flex items-center justify-between space-y-2 md:space-x-4 px-2">
        <div className="bg-[#F4F5FB] rounded-[90px] hidden md:flex items-center px-3 max-w-[297px] w-full gap-3 h-[57px]">
          <Search color="#333333" size={18} />

          <input
            type="search"
            placeholder="Search Products..."
            className="placeholder:text-[#333333] font-satoshi font-medium text-[#333333] bg-inherit outline-none border-none  "
          />
        </div>

        <div className="flex items-center space-x-2 md:space-x-4">
          <div className="relative">
            <button
              className=""
              onClick={() => setShowOptions((prev) => !prev)}
            >
              <UserRound />
            </button>
            <AccountOptions showOptions={showOptions} />
          </div>

          <div className="relative flex">
            <button
              type="button"
              className=""
              onClick={() => setShowCart(true)}
            >
              <ShoppingCart />
            </button>
            <sub className="bg-[#fda600] absolute -top-3 -right-3 font-bold flex justify-center items-center w-5 h-5 rounded-full">
              0
            </sub>
            <CartItems isOpen={showCart} onClose={() => setShowCart(false)} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default NewNavbar;
