"use client";
import React, { useState } from "react";
import Image from "next/image";
import google from "../../../public/google.svg";
import { signUp } from "@/app/actions/auth";
import { useFormState } from "react-dom";
import Button from "./Button";
import { Eye, EyeOff } from "lucide-react";

const SignUpForm = ({ role }: { role: "Vendor" | "Client" }) => {
  const [isEmail, setIsEmail] = useState(true);
  const [isPassword, setIsPassword] = useState(false);
  const initialState = { errors: {} };
  const [state, formAction] = useFormState(signUp, initialState);
  console.log("Sign up state", state);
  return (
    <>
      <form
        action={formAction}
        className="w-full flex flex-col items-center gap-6 pt-10"
      >
        {state.call_error && (
          <div className="py-3 px-2 border-l-[6px] border-red-600 bg-red-50">
            {state.call_error}
          </div>
        )}
        <div className="w-full flex flex-col items-center relative pb-2">
          <p
            className={`flex items-center justify-between w-full gap-4 p-2 ${
              !isEmail ? "flex-row-reverse" : "flex-row"
            }`}
          >
            <label
              htmlFor="email"
              onClick={() => setIsEmail(true)}
              className={`text-[15px] leading-5 hover:text-black cursor-pointer transition-all px-[15px] py-[7px] rounded-[15px] ${
                isEmail
                  ? "text-white   bg-[#fda600]"
                  : "text-black/60 font-light bg-[#d9d9d9]"
              }`}
            >
              Email
            </label>
            <label
              htmlFor="phone_number"
              onClick={() => setIsEmail(false)}
              className={`text-[15px] leading-5 hover:text-black cursor-pointer transition-all px-[15px] py-[7px] rounded-[15px] ${
                !isEmail
                  ? "text-white  bg-[#fda600]"
                  : "text-black/60 font-light bg-[#d9d9d9]"
              }`}
            >
              Phone number
            </label>
          </p>
          <input
            type="text"
            name={isEmail ? "email" : "phone"}
            className="box-border w-full bg-white border-[1.5px] outline-none border-[#D9D9D9] rounded-[70px] px-3 py-4"
            placeholder={
              isEmail ? "eg: mystoreemail@email.com" : "eg: 09012345678"
            }
          />
          {state?.errors?.email && isEmail ? (
            <span className="absolute left-0 -bottom-2 text-xs text-red-600">
              {state.errors?.email}
            </span>
          ) : null}
          {state.errors?.phone && !isEmail ? (
            <span className="absolute left-0 -bottom-2  text-xs text-red-600">
              {state.errors?.phone}
            </span>
          ) : null}
        </div>
        <div className="w-full flex flex-col items-center relative pb-2">
          <p className="flex items-center justify-start w-full gap-2 p-2">
            <label
              htmlFor="password"
              className="text-[15px] leading-5 text-[#101010] cursor-pointer"
            >
              Password
            </label>
          </p>
          <div className="relative w-full">
            <input
              type={!isPassword ? "password" : "text"}
              name="password"
              id="password"
              className="box-border bg-white outline-none w-full border-[1.5px] border-[#D9D9D9] rounded-[70px] px-3 py-4"
              placeholder="Enter password "
            />
            <button
              type="button"
              onClick={() => setIsPassword((prev) => !prev)}
              className="absolute top-4 right-4"
            >
              {!isPassword ? (
                <Eye color="#282828" size={20} />
              ) : (
                <EyeOff color="#282828" size={20} />
              )}
            </button>
          </div>

          {state.errors?.password && (
            <span className="absolute left-0 -bottom-2  text-xs text-red-600">
              {state.errors?.password}
            </span>
          )}
        </div>
        <div className="w-full flex flex-col items-center relative pb-2">
          <p className="flex items-center justify-start w-full  gap-2 p-2">
            <label
              htmlFor="confirm_password"
              className="text-[15px] leading-5 text-[#101010] cursor-pointer"
            >
              Confirm Password
            </label>
          </p>
          <input
            type="password"
            name="password2"
            id="confirm_password"
            className="box-border bg-white outline-none w-full border-[1.5px] border-[#D9D9D9] rounded-[70px] px-3 py-4"
            placeholder="Confirm password "
          />
          {state.errors?.password2 && (
            <span className="absolute left-0 -bottom-2 text-xs text-red-600">
              {state.errors?.password2}
            </span>
          )}
        </div>
        <input type="hidden" value={role} name="role" />

        <Button title="Sign Up" />
        <div className="w-full max-w-[423px] flex items-center gap-3 ">
          <span className="w-1/2 h-[1px] bg-[#D9D9D9]" />
          <span className="text-[13px] text-[#282828] leading-[17.55px]">
            Or
          </span>
          <span className="w-1/2 h-[1px] bg-[#D9D9D9]" />
        </div>
        <button className="bg-[#fff] w-full outline-none border-[1.2px] border-[#D9D9D9] shd  flex items-center justify-center gap-3 py-[17px] text-[#282828] text-lg font-medium leading-6 rounded-[70px]">
          <Image src={google} alt="google" />
          Sign Up with Google
        </button>
      </form>
    </>
  );
};

export default SignUpForm;
