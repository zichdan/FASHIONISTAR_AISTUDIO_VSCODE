"use client";
import React, { useState } from "react";
interface CollapsibleProp {
  title: string;
  text: string;
  isOpen: Boolean;
  onClick: () => void;
}

const Collapsible = ({ title, text, onClick, isOpen }: CollapsibleProp) => {
  return (
    <div className="flex flex-col w-full gap-0.5 ">
      <div className="flex w-full gap-x-3 items-center">
        <button
          className={`transition duration-200 outline-none ${
            isOpen ? "rotate-180 " : "rotate-0 "
          }`}
          onClick={onClick}
        >
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M13.5 6.75004C13.5 6.75004 10.1858 11.25 9 11.25C7.8141 11.25 4.5 6.75 4.5 6.75"
              stroke="black"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </button>
        <h2 className="text-black text-[15px] font-satoshi font-medium ">
          {title}
        </h2>
      </div>
      {isOpen ? (
        <div className="">
          {" "}
          <p className="text-[13px] text-[#222] capitalize text-wrap">{text}</p>
        </div>
      ) : null}
    </div>
  );
};

export default Collapsible;
