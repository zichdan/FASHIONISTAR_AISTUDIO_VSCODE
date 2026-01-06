import React from "react";
import Link from "next/link";
import {
  Radio,
  Heart,
  Settings,
  UserRoundCheck,
  LogOut,
  UserRound,
} from "lucide-react";

const AccountOptions = ({ showOptions }: { showOptions: boolean }) => {
  return (
    <div
      style={{ boxShadow: "0px 4px 25px 0px #0000001A" }}
      className={`w-[284px] min-h-[200px] p-5 rounded-[5px] bg-white absolute right-0 z-40 ${
        showOptions ? "flex flex-col gap-3" : "hidden"
      }`}
    >
      <Link
        href=""
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <UserRound />
        My Account
      </Link>
      <Link
        href="/"
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <Radio /> Order tracking
      </Link>
      <Link
        href="/"
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <Heart /> My Wishlist
      </Link>
      <Link
        href="/"
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <Settings /> Settings
      </Link>
      <Link
        href="/"
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <UserRoundCheck /> Register as a vendor
      </Link>
      <Link
        href="/login"
        className="text-black font-raleway font-semibold text-xl flex items-center gap-2 hover:text-[#01454A]"
      >
        <LogOut /> Sign in
      </Link>
    </div>
  );
};

export default AccountOptions;
