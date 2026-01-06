import React from "react";

const Category = () => {
  return (
    <div className="space-y-10 w-full">
      <div className="space-y-2 ">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          {" "}
          Category
        </h2>
        <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          You can choose more than one category
        </p>
      </div>
      <div className="flex gap-10">
        <div className="flex flex-col gap-2 w-[47%] px-3">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Category
          </label>
          <select
            name="category"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          >
            <option>Senator</option>
            <option>Agbada</option>
            <option>Kaftan</option>
          </select>
        </div>
        <div className="flex flex-col gap-2 w-[47%] px-3">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Brands
          </label>
          <select
            name="brands"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          >
            <option>Mens Senator</option>
            <option>Agbada</option>
            <option>Kaftan</option>
          </select>
        </div>
      </div>
    </div>
  );
};

export default Category;
