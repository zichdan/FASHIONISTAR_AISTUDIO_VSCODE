"use client";
import React, { useRef } from "react";
import { reviews } from "../utils/mock";
import ReviewCard from "./ReviewCard";

const ReviewScroll = () => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollAmount = 600;
  const scrollLeft = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollBy({
        left: -scrollAmount,
        behavior: "smooth",
      });
    }
  };
  const scrollRight = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollBy({
        left: scrollAmount,
        behavior: "smooth",
      });
    }
  };

  const review = reviews.map((rw) => {
    return <ReviewCard review={rw} key={rw.user.image} />;
  });
  return (
    <div className="flex flex-col gap-10">
      <div
        ref={scrollRef}
        className=" px-5 md:px-8 lg:pl-28 hide_scrollbar gap-6 grid grid-flow-col auto-cols-[65%] md:auto-cols-[40%] overflow-x-auto overscroll-contain"
      >
        {review}
      </div>
      <div className="px-5 md:px-8 lg:px-28 flex gap-2 items-center">
        <button
          onClick={scrollLeft}
          className=" w-10 h-10 outline-none hover:border-[#fda600] flex justify-center items-center border border-black rounded-full"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M4 12H20"
              stroke="black"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M8.99996 17C8.99996 17 4.00001 13.3176 4 12C3.99999 10.6824 9 7 9 7"
              stroke="black"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <button
          onClick={scrollRight}
          className=" w-10 h-10 outline-none hover:border-[#fda600] flex justify-center items-center border border-black rounded-full"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M20 12H4"
              stroke="black"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M15 17C15 17 20 13.3176 20 12C20 10.6824 15 7 15 7"
              stroke="black"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>
    </div>
  );
};

export default ReviewScroll;
