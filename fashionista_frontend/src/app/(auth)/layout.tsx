import Image from "next/image";
import React from "react";
import bg_auth from "../../../public/bg-auth.svg";
import logo from "../../../public/logo.svg";

const layout = ({ children }: Readonly<{ children: React.ReactNode }>) => {
  return (
    <div className=" bg-[#F4F3EC] pb-10">
      <div className="w-full px-10 z-30 h-[100px] bg-white shadow-md flex items-center fixed top-0 left-0">
        <div className=" flex items-center">
          <Image
            src="/logo.svg"
            width={55}
            height={54}
            alt="logo"
            className=""
          />
          <h2 className="font-bon_foyage px-3 text-4xl text-black">
            Fashionistar
          </h2>
        </div>
      </div>
      <div className="mt-[120px] w-full max-w-[675px] min-h-[500px] rounded-[10px] border border-[#d9d9d9] font-satoshi p-10 justify-evenly mx-auto bg-white shadow-md">
        {children}
      </div>
    </div>
  );
};

export default layout;
