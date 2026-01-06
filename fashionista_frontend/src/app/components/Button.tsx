"use client";
import React from "react";
import { useFormStatus } from "react-dom";
import { Loader2 } from "lucide-react";

const Button = ({ title }: { title: string }) => {
  const { pending } = useFormStatus();
  return (
    <button
      aria-disabled={pending}
      disabled={pending}
      className="bg-[#FDA600] shd w-full outline-none  py-[17px] text-white text-lg font-bold rounded-[70px] flex justify-center items-center"
    >
      {pending ? <Loader2 className="animate-spin" /> : title}
      {/* <span className="w-10 h-10 rounded-full bg-transparent border-4 border-white animate-spin" /> */}
      {/* <Loader2 /> */}
    </button>
  );
};

export default Button;
