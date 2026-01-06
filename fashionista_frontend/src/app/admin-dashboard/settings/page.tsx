import React from "react";
import Image from "next/image";
import sapphire from "../../../../public/vendor/sapphire.svg";

const page = () => {
  return (
    <div className="flex justify-between ">
      <div className="w-[118px] h-[118px] rounded-full bg-[#fda600]">
        <Image
          src={sapphire}
          width={100}
          height={100}
          alt="Profile image"
          className="w-full h-full rounded-full "
        />
      </div>
      <div style={{ width: "calc(100% - 120px)" }} className="px-5">
        <form className="flex flex-wrap gap-2 gap-y-5 pb-10" id="settings">
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="first_name">First name</label>
            <input
              id="first_name"
              type="text"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="last_name">Last name</label>
            <input
              id="last_name"
              type="text"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="phone_number">Phone Number</label>
            <input
              id="phone_number"
              type="text"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="date_of_birth">Date of Birth</label>
            <input
              id="date_of_birth"
              type="text"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
          <div className="flex flex-col gap-2 w-[48%]">
            <label htmlFor="address">Contact Address</label>
            <input
              id="address"
              type="text"
              className="px-5 w-full bg-inherit outline-none rounded-[70px] h-[70px] border-[1.5px] border-[#d9d9d9] text-[15px] font-satoshi text-[#282828] "
            />
          </div>
        </form>
        <div className="flex items-center gap-5 py-10 border-t-[0.8px] border-[#d9d9d9]">
          <div className="w-[350px] h-[122px] rounded-[10px] border bg-inherit border-[#d9d9d9] p-5 flex items-center justify-between">
            <div className="flex flex-col justify-between space-y-3">
              <h3 className="font-satoshi text-2xl leading-7 text-black">
                {" "}
                Password change
              </h3>
              <p className="font-satoshi text-sm leading-5 text-black">
                {" "}
                You can reset and change your password by clicking here
              </p>
            </div>
            <button className="py-2.5 px-[15px] rounded-[5px] bg-[#d9d9d9] font-satoshi text-[#282828]">
              Change
            </button>
          </div>
          <div className="w-[350px] h-[122px] rounded-[10px] border bg-inherit border-[#d9d9d9] p-5 flex items-center justify-between">
            <div className="flex flex-col justify-between space-y-3">
              <h3 className="font-satoshi text-2xl leading-7 text-black">
                {" "}
                Remove account
              </h3>
              <p className="font-satoshi text-sm leading-5 text-black">
                {" "}
                Once you delete your account, there’s no going back.
              </p>
            </div>
            <button className="py-2.5 px-[15px] rounded-[5px] bg-[#d9d9d9] font-satoshi text-[#282828]">
              Deactivate
            </button>
          </div>
        </div>
        <div className="flex items-center justify-end gap-8 w-full py-8">
          <button className="font-medium text-lg leading-6 text-[#4E4E4E] hover:text-black">
            Cancel
          </button>

          <button
            form="settings"
            className="py-2 px-5 bg-[#fda600] outline-none font-medium text-black hover:text-white grow-0"
          >
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
};

export default page;
