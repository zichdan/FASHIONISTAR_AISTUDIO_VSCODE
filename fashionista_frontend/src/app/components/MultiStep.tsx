"use client";
import { useState } from "react";
import { motion } from "framer-motion";
import { createNewProduct } from "../utils/libs";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, SubmitHandler } from "react-hook-form";
import { FormSchema } from "../utils/schema";
import { newProduct } from "../actions/vendor";
import Prices from "./AddProduct/Prices";
import BasicInformation from "./AddProduct/BasicInformation";
import Category from "./AddProduct/Category";
import Gallery from "./AddProduct/Gallery";
import Specification from "./AddProduct/Specification";
import Sizes from "./AddProduct/Sizes";
import Color from "./AddProduct/Color";
import { useAddProductContext } from "../context/addProductContext";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useRouter } from "next/navigation";

type Inputs = z.infer<typeof FormSchema>;

const steps = [
  {
    id: 1,
    title: "Basic Information",
    fields: ["title", "description", "image_1"],
  },
  {
    id: 2,
    title: "Prices",
    fields: [
      "sales_price",
      "regular_price",
      "shipping_amount",
      "stock_qty",
      "tag",
      "total_price",
    ],
  },
  {
    id: 3,
    title: "Category",
    fields: ["category", "brands"],
  },
  {
    id: 4,
    title: "Gallery",
    fields: ["image_2", "image_3", "image_4", "video"],
  },
];

export default function Form() {
  const searchParams = useSearchParams();
  const step = searchParams.get("step");
  const { newProductFields, updateNewProductField } = useAddProductContext();
  const [previousStep, setPreviousStep] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const delta = currentStep - previousStep;

  const {
    register,
    handleSubmit,
    watch,
    reset,
    trigger,
    setValue,
    formState: { errors },
  } = useForm<Inputs>({
    resolver: zodResolver(FormSchema),
  });

  const { back } = useRouter();
  const processForm: SubmitHandler<Inputs> = async (data) => {
    await newProduct(data);
    // await createNewProduct(data);
    reset();
  };

  type FieldName = keyof Inputs;

  const next = async () => {
    const fields = steps[currentStep].fields;
    const output = await trigger(fields as FieldName[], { shouldFocus: true });

    if (!output) return;

    if (currentStep < steps.length - 1) {
      if (currentStep === steps.length - 1) {
        await handleSubmit(processForm)();
      }
      setPreviousStep(currentStep);
      setCurrentStep((step) => step + 1);
    }
  };

  // const back = () => {
  //   if (currentStep > 0) {
  //     setPreviousStep(currentStep);
  //     setCurrentStep((step) => step - 1);
  //   }
  // };

  return (
    <div className="p-5 pt-12 md:p-6 md:pb-20 w-full md:w-[75%] h-[680px] bg-transparent hide_scrollbar overflow-auto relative top-[16%] md:fixed md:top-[16%] right-0 flex flex-col gap-8 z-10">
      <div className="bg-[#fff] rounded-[10px] p-[15px] md:p-6  w-full h-fit relative pb-10 ">
        <ul className="flex items-center justify-between md:justify-end left-0 absolute -top-12 md:top-6 md:right-6 md:gap-5 font-satoshi">
          <Link
            href="/dashboard/products"
            className={`font-medium text-[11px] md:text-sm text-black px-1 md:px-2 py-3 ${
              !step ? "bg-[#fda600]" : ""
            } `}
          >
            Basic Information
          </Link>
          <Link
            href="/dashboard/products?step=prices"
            className={`font-medium text-[11px] md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "prices" && "bg-[#fda600]"
            }`}
          >
            Prices
          </Link>
          <Link
            href="/dashboard/products?step=category"
            className={`font-medium text-[11px] md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "category" && "bg-[#fda600]"
            }`}
          >
            Category
          </Link>
          <Link
            href="/dashboard/products?step=gallery"
            className={`font-medium text-[11px] md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "gallery" && "bg-[#fda600]"
            }`}
          >
            Gallery
          </Link>
          <Link
            href="/dashboard/products?step=specification"
            className={`font-medium text-[11px]  md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "specification" && "bg-[#fda600]"
            }`}
          >
            Specification
          </Link>
          <Link
            href="/dashboard/products?step=sizes"
            className={`font-medium text-[11px] md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "sizes" && "bg-[#fda600]"
            }`}
          >
            Size
          </Link>
          <Link
            href="/dashboard/products?step=color"
            className={`font-medium text-[11px] md:text-sm transition-colors text-black px-1.5 md:px-2 py-3 ${
              step == "color" && "bg-[#fda600]"
            }`}
          >
            Color
          </Link>
        </ul>
        <>
          {!step && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <BasicInformation
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "prices" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Prices
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "category" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Category
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "gallery" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Gallery
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "specification" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Specification
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "sizes" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Sizes
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
          {step == "color" && (
            <motion.div
              initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Color
                newProductFields={newProductFields}
                updateNewProductField={updateNewProductField}
              />
            </motion.div>
          )}
        </>
      </div>
      <div className="flex items-center justify-end gap-8 w-full py-6">
        <button
          onClick={back}
          type="button"
          form={!step ? "basic-information" : step}
          className={`py-2.5 px-[30px] bg-transparent outline-none font-medium text-lg leading-6 text-[#4E4E4E] hover:text-black disabled:cursor-not-allowed disabled:text-[#d9d9d9]`}
        >
          Back
        </button>

        <button
          onClick={next}
          form={!step ? "basic" : step}
          type="submit"
          className="py-2.5 px-[30px] bg-[#fda600] outline-none font-medium text-black hover:text-white grow-0"
        >
          Continue
        </button>
      </div>
    </div>
  );
}
