import React from "react";
import { FieldErrors, UseFormRegister } from "react-hook-form";
import { NewProductType } from "@/types";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
import { CategoryAction } from "@/app/actions/vendor";

const Category = ({
  newProductFields,
  updateNewProductField,
}: {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
}) => {
  const handleInputChange = (
    e: React.ChangeEvent<HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    updateNewProductField({ [e.target.name]: e.target.value });
  };
  return (
    <form action={CategoryAction} id="category" className="space-y-10 w-full">
      <div className="space-y-2 ">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          {" "}
          Category
        </h2>
        <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          You can choose more than one category
        </p>
      </div>
      <div className="flex flex-wrap gap-10">
        <div className="flex flex-col gap-2 w-full md:w-[47%] px-3">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Category
          </label>
          <select
            // name="category"
            // {...register("category")}
            name="category"
            onChange={handleInputChange}
            defaultValue={newProductFields["category"]}
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          >
            <option>Senator</option>
            <option>Agbada</option>
            <option>Kaftan</option>
          </select>
          {/* {errors.category?.message && (
            <p className="mt-2 text-sm text-red-400">
              {errors.category.message}
            </p>
          )} */}
        </div>
        <div className="flex flex-col gap-2 w-full md:w-[47%] px-3">
          <label className="font-satoshi text-[15px] leading-5 text-[#000]">
            Brands
          </label>
          <select
            name="brands"
            defaultValue={newProductFields["brands"]}
            onChange={handleInputChange}
            className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
          >
            <option>Mens Senator</option>
            <option>Agbada</option>
            <option>Kaftan</option>
          </select>
          {/* {errors.brands?.message && (
            <p className="mt-2 text-sm text-red-400">{errors.brands.message}</p>
          )} */}
        </div>
      </div>
    </form>
  );
};

export default Category;
