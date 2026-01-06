"use client";
import { NewProductType } from "@/types";
import React from "react";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
import { PricesAction } from "@/app/actions/vendor";

const Prices = ({
  newProductFields,
  updateNewProductField,
}: {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
}) => {
  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    updateNewProductField({ [e.target.name]: e.target.value });
  };
  console.log("New Product details", newProductFields);
  return (
    <form id="prices" action={PricesAction} className="space-y-10 w-full">
      <div className="space-y-2">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          Prices
        </h2>
        <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          Add prices to product tags
        </p>
      </div>
      <div className="flex flex-wrap gap-x-10 gap-y-10">
        <div className="flex flex-col gap-2 w-full md:w-[47%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Sales price
          </label>
          <input
            type="text"
            name="sales_price"
            onChange={handleInputChange}
            defaultValue={newProductFields["sales_price"]}
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-black text-[#000]"
          />
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[47%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Regular Price
          </label>
          <input
            type="text"
            name="regular_price"
            onChange={handleInputChange}
            defaultValue={newProductFields["regular_price"]}
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          />
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[47%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Shipping Amount
          </label>
          <input
            type="text"
            name="shipping_amount"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
            value={1000}
            readOnly
          />
          <span className="font-satoshi font-medium text-xs text-[#555555]">
            Note: it’s automatic 1000 for people living in lagos state
          </span>
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[47%]">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Stock Qty
          </label>
          <input
            type="text"
            name="stock_qty"
            defaultValue={newProductFields["stock_qty"]}
            onChange={handleInputChange}
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          />
        </div>
        <div className="flex flex-col gap-2 w-full">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Tag
          </label>
          <input
            type="text"
            name="tag"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
            defaultValue={newProductFields["tag"]}
            onChange={handleInputChange}
          />
          <span className="font-satoshi font-medium text-xs text-[#555555]">
            Note: Separate tags with commas
          </span>
        </div>
        <div className="flex flex-col gap-2 w-full">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Total Price
          </label>
          <input
            type="text"
            name="total_price"
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
            onChange={handleInputChange}
            defaultValue={newProductFields["total_price"]}
          />
        </div>
      </div>
      {/* <button className="py-2.5 px-[30px] bg-[#fda600] outline-none font-medium text-black hover:text-white grow-0">
        Continue
      </button> */}
    </form>
  );
};

export default Prices;
