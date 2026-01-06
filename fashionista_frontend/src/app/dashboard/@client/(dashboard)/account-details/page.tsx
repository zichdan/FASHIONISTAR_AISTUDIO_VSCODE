import React from "react";

const page = () => {
  return (
    <div className="space-y-10 pb-10">
      <div>
        <h3 className="font-satoshi font-medium text-3xl text-black">
          Account details
        </h3>
        <p className="font-satoshi text-xl text-black py-5">
          You can view, edit and delete your saved addresses.
        </p>
      </div>
      <form
        action=""
        className="flex items-center justify-between flex-wrap gap-y-5 bg-white px-[30px] py-20 rounded-[10px] shadow-card_shadow"
      >
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="first_name" className="text-xl text-black">
            First Name
          </label>
          <input
            type="text"
            name="first_name"
            id="first_name"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="last_name" className="text-xl text-black">
            Last Name
          </label>
          <input
            type="text"
            name=""
            id="last_name"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex flex-col w-full gap-2">
          <label htmlFor="email" className="text-xl text-black">
            Email Address
          </label>
          <input
            type="email"
            name="email"
            id="email"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="password" className="text-xl text-black">
            Current Password
          </label>
          <input
            type="password"
            name="password"
            id="password"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex flex-col w-full md:w-[48%] gap-2">
          <label htmlFor="new_password" className="text-xl text-black">
            New Password
          </label>
          <input
            type="password"
            name="new_password"
            id="new_password"
            className="w-full rounded-[70px] h-[70px] border-[1.5px] border-[#D9D9D9] bg-inherit outline-none px-3 text-black"
          />
        </div>
        <div className="flex items-center justify-end gap-4 w-full pt-10">
          <button className="py-5 px-[53px] bg-white text-xl hover:text-black outline-none font-medium font-satoshi text-[#858585]">
            Cancel
          </button>
          <button className="py-5 px-[53px] bg-[#fda600] text-xl  outline-none font-medium font-satoshi text-black hover:text-white">
            Save Changes
          </button>
        </div>
      </form>
    </div>
  );
};

export default page;
