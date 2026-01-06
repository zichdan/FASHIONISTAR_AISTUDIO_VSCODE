"use client";
import { NewProductType } from "@/types";
import React, { useState } from "react";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
import { SizesAction } from "@/app/actions/vendor";
import { useFormState } from "react-dom";

const Sizes = ({
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
  const fields = [
    { id: crypto.randomUUID(), title: "sizes" },
    { id: crypto.randomUUID(), title: "price" },
  ];
  const [allFields, setAllFields] = useState(fields);
  const [isField, setIsField] = useState(false);
  const [newField, setNewField] = useState({ id: "", title: "" });
  const [state, formAction] = useFormState(SizesAction, null);
  console.log(state);

  // const inputFields = allFields.map((field: { id: string; title: string }) => {
  //   return (
  //     <div key={field.id} className="flex flex-col w-full md:w-[47%]">
  //       <label className="capitalize text-[15px] leading-5 text-[#000]">
  //         {field.title}
  //       </label>
  //       <input
  //         type="text"
  //         name={field.title}
  //         value={formData.title || ""}
  //         onChange={(e) => update({ ...formData, title: e.target.value })}
  //         className="rounded-[70px] text-black border-[#D9D9D9] border-[1.5px] w-full h-[60px] outline-none px-3"
  //       />
  //     </div>
  //   );
  // });
  return (
    <form id="sizes" className="flex flex-col gap-8 w-full" action={formAction}>
      <div className="space-y-2 ">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          Sizes
        </h2>
        {/* <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          Add any specification for your product
        </p> */}
      </div>
      <div className="min-h-[300px] flex flex-col justify-between">
        <div className="flex flex-wrap gap-6">
          <div className="flex flex-col w-full md:w-[47%]">
            <label className="capitalize text-[15px] leading-5 text-[#000]">
              Sizes
            </label>
            <input
              type="text"
              name="size"
              defaultValue={newProductFields.sizes.size}
              onChange={(e) =>
                updateNewProductField({
                  ...newProductFields,
                  sizes: {
                    ...newProductFields.sizes,
                    size: e.target.value,
                  },
                })
              }
              className="rounded-[70px] text-black border-[#D9D9D9] border-[1.5px] w-full h-[60px] outline-none px-3"
            />
          </div>
          <div className="flex flex-col w-full md:w-[47%]">
            <label className="capitalize text-[15px] leading-5 text-[#000]">
              Price
            </label>
            <input
              type="text"
              name="size_price"
              defaultValue={newProductFields.sizes.price}
              onChange={(e) =>
                updateNewProductField({
                  ...newProductFields,
                  sizes: {
                    ...newProductFields.sizes,
                    price: e.target.value,
                  },
                })
              }
              className="rounded-[70px] text-black border-[#D9D9D9] border-[1.5px] w-full h-[60px] outline-none px-3"
            />
          </div>
        </div>

        <div className="py-6">
          <button
            onClick={() => setIsField(true)}
            className="text-black text-lg leading-6 font-medium font-satoshi px-4 py-4 bg-[#fda600]"
          >
            + Add more sizes
          </button>
        </div>
      </div>
    </form>
  );
};

export default Sizes;
