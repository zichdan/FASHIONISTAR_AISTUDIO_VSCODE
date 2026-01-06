"use client";
import Link from "next/link";
import { motion } from "framer-motion";
import { useState } from "react";
import SignUpForm from "@/app/components/SignUpForm";

const Page = () => {
  const [role, setRole] = useState<"Vendor" | "Client" | undefined>();
  return (
    <>
      <div className=" ">
        <h2 className="font-satoshi font-medium text-3xl leading-10 text-black">
          Sign Up
        </h2>
        <p className="font-satoshi text-[15px] leading-5 text-[#282828]">
          Already have an account?{" "}
          <Link href="/login" className="font-semibold ">
            Login{" "}
          </Link>
        </p>
      </div>
      {!role && (
        <motion.div
          initial={{ x: 1 >= 0 ? "50%" : "-50%", opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.3, ease: "easeInOut" }}
        >
          <div className="flex flex-col gap-5 py-4">
            <div
              onClick={() => setRole("Vendor")}
              className="hover:bg-[#D9D9D9] bg-white p-4 hover:shadow-md border border-[#d9d9d9] cursor-pointer"
            >
              <h3 className="font-medium text-xl leading-[27px] text-black">
                Vendor
              </h3>
              <p className="font-satoshi leading-[21.6px] text-[#282828]">
                Upload your work and fashion collections
              </p>
            </div>

            <div
              onClick={() => setRole("Client")}
              className="hover:bg-[#D9D9D9] bg-white p-4 hover:shadow-md border border-[#d9d9d9] cursor-pointer"
            >
              <h3 className="font-medium text-xl leading-[27px] text-black">
                Client
              </h3>
              <p className="font-satoshi leading-[21.6px] text-[#282828]">
                Get your designed and tailored dress
              </p>
            </div>
          </div>
        </motion.div>
      )}
      {role && (
        <motion.div
          initial={{ x: 1 >= 0 ? "50%" : "-50%", opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.3, ease: "easeInOut" }}
        >
          <SignUpForm role={role} />
        </motion.div>
      )}
    </>
  );
};
export default Page;
