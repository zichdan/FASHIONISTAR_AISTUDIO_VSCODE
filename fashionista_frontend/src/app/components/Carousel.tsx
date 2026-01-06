"use client";

import Image from "next/image";
import couple from "../../../public/couple_assets.svg";
import man from "../../../public/asset4.svg";
import man2 from "../../../public/man2_asset.svg";
import { useState, useEffect } from "react";

const Slider = () => {
  const [current, setCurrent] = useState(0);
  const slides = [
    {
      text: " Your Style with the Latest Fashion Trends.",
      image: couple,
      highlight: "Style",
    },
    {
      text: "  We offer amazing discounts on first order.",
      image: man,
      highlight: "discounts",
    },
    {
      text: "Get your exact measurement without stress",
      image: man2,
      highlight: "measurement",
    },
  ];
  useEffect(() => {
    const intervalId = setInterval(() => {
      setCurrent((prevCurrent) =>
        prevCurrent === slides.length - 1 ? 0 : prevCurrent + 1
      );
    }, 5000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
  }, [slides.length]);
  function highlightText(text: string, highlight: string) {
    const parts = text.split(new RegExp(`(${highlight})`, "gi"));
    return parts.map((part, index) =>
      part.toLowerCase() === highlight.toLowerCase() ? (
        <span key={index} className="text-[#fda600]">
          {part}
        </span>
      ) : (
        part
      )
    );
  }
  const sliders = slides.map((slide, index) => {
    return (
      <div className="w-full flex-shrink-0" key={index}>
        <div className="flex justify-center bg-[#EDE7D9]  md:bg-transparent">
          <p className="font-bon_foyage text-5xl px-6 py-2 leading-[47.62px] md:text-8xl md:leading-[95px] text-center text-black  md:w-1/2 md:px-10 ">
            {highlightText(slide.text, slide.highlight)}
          </p>
        </div>
        <div className="relative flex justify-center">
          <div className="z-10 absolute -top-12">
            <Image src={slide.image} alt="" className="w-full h-full" />
          </div>
        </div>
      </div>
    );
  });

  return (
    <div className="overflow-hidden relative mt-5 ">
      <div
        className={`flex transition ease-out duration-400 h-screen`}
        style={{
          transform: `translateX(-${current * 100}%)`,
        }}
      >
        {sliders}
      </div>
    </div>
  );
};
export default Slider;

{
  /* <div>
        <div className="flex justify-center ">
          <p className="font-bon_foyage text-8xl leading-[95px] text-center text-black  w-1/2 px-10 ">
            Your <span className="text-[#fda600]">Style</span> with the Latest
            Fashion Trends.
          </p>
        </div>
        <div className="relative flex justify-center">
          <div className="z-10 absolute -top-16">
            <Image src={couple} alt="" />
          </div>
        </div>
      </div>
      <div>
        <div className="flex justify-center ">
          <p className="font-bon_foyage text-8xl leading-[95px] text-center text-black  w-1/2 px-10 ">
            We offer amazing<span className="text-[#fda600]">discounts</span> on
            first order.
          </p>
        </div>
        <div className="relative flex justify-center">
          <div className="z-10 absolute -top-16">
            <Image src={man} alt="" />
          </div>
        </div>
      </div>
      <div>
        <div className="flex justify-center ">
          <p className="font-bon_foyage text-8xl leading-[95px] text-center text-black  w-1/2 px-10 ">
            Get your exact <span className="text-[#fda600]"> measurement</span>{" "}
            without stress
          </p>
        </div>
        <div className="relative flex justify-center">
          <div className="z-10 absolute -top-16">
            <Image src={man2} alt="" />
          </div>
        </div>
      </div> */
}
