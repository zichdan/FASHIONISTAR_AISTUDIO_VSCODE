"use client";
import { NewProductType } from "@/types";
import Image from "next/image";
import React, { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { BasicInformationAction } from "@/app/actions/vendor";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
// import { FieldErrors, UseFormRegister, UseFormSetValue } from "react-hook-form";

const BasicInformation = ({
  newProductFields,
  updateNewProductField,
}: {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
}) => {
  const [preview, setPreview] = useState<string | undefined>(undefined);
  const [fileName, setFileName] = useState<string>("");

  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();

      reader.onloadend = () => {
        setPreview(reader.result as string);

        console.log(URL.createObjectURL(file));

        updateNewProductField({ image_1: file });
        setFileName(newProductFields?.image_1.name);
      };

      reader.readAsDataURL(file);
    },
    [newProductFields?.image_1.name, updateNewProductField]
  );

  // const { getRootProps, getInputProps } = useDropzone({
  //   accept: {
  //     "image/*": [".jpeg", ".jpg", ".png"],
  //   },
  //   useFsAccessApi: false,
  //   onDrop,
  //   onError: (err) => console.log(err),
  // });
  // const onDrop = useCallback((acceptedFiles: any) => {
  //   const file = new FileReader();

  //   file.onload = function () {
  //     setPreview(file.result as string);
  //     setFileName(file?.name);
  //     // const img = decoder.decode(file.result);
  //     console.log(file);

  //     updateNewProductField({ image_1: file.result as File });
  //   };

  //   file.readAsDataURL(acceptedFiles[0]);
  // }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      "image/*": [".jpeg", ".jpg", ".png"],
    },
    useFsAccessApi: false,
    onDrop,
    onError: (err) => console.log(err),
  });

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    updateNewProductField({ [e.target.name]: e.target.value });
  };

  return (
    <form
      action={BasicInformationAction}
      id="basic"
      className="flex flex-col gap-8 w-full shrink-0"
    >
      <div className="space-y-2">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          Upload Image
        </h2>
        <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          Upload captivating and clear images to make your product stand out
        </p>
      </div>
      <div className="flex flex-col md:flex-row gap-6">
        <div
          className="w-full md:w-1/2 bg-[#F5F5F5] shadow flex flex-col justify-center items-center gap-2 min-h-[471px]"
          {...getRootProps()}
        >
          <input {...getInputProps()} name="image_1" id="image_1" />
          {newProductFields.image_1 ? (
            <div className="max-h-full h-full w-full">
              <Image
                src={URL.createObjectURL(newProductFields.image_1)}
                alt="Preview"
                width={200}
                height={200}
                className="w-full h-full object-cover"
              />
            </div>
          ) : (
            <>
              <svg
                width="37"
                height="38"
                viewBox="0 0 37 38"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M9.25 28.2107C9.44841 30.2278 9.89682 31.5855 10.9102 32.5989C12.7279 34.4167 15.6535 34.4167 21.5046 34.4167C27.3556 34.4167 30.2813 34.4167 32.0989 32.5989C33.9167 30.7813 33.9167 27.8556 33.9167 22.0046C33.9167 16.1535 33.9167 13.2279 32.0989 11.4102C31.0855 10.3968 29.7278 9.94841 27.7107 9.75"
                  stroke="black"
                  strokeWidth="2.3125"
                />
                <path
                  d="M3.08301 15.9163C3.08301 10.1023 3.08301 7.19536 4.88918 5.38918C6.69536 3.58301 9.60235 3.58301 15.4163 3.58301C21.2303 3.58301 24.1374 3.58301 25.9435 5.38918C27.7497 7.19536 27.7497 10.1023 27.7497 15.9163C27.7497 21.7303 27.7497 24.6374 25.9435 26.4435C24.1374 28.2497 21.2303 28.2497 15.4163 28.2497C9.60235 28.2497 6.69536 28.2497 4.88918 26.4435C3.08301 24.6374 3.08301 21.7303 3.08301 15.9163Z"
                  stroke="black"
                  strokeWidth="2.3125"
                />
                <path
                  d="M3.08301 17.6408C4.03733 17.5194 5.00214 17.4596 5.96856 17.4616C10.057 17.3861 14.0452 18.5007 17.2218 20.6068C20.1678 22.5601 22.2378 25.2481 23.1247 28.2497"
                  stroke="black"
                  strokeWidth="2.3125"
                  strokeLinejoin="round"
                />
                <path
                  d="M20.042 11.292H20.0559"
                  stroke="black"
                  strokeWidth="3.08333"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              {isDragActive ? (
                <p>Drop the file here ...</p>
              ) : (
                <p className="font-satoshi font-medium text-black">
                  Click to upload or drag and drop
                </p>
              )}

              <span className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
                SVG, PNG, JPEG or GIF
              </span>
              <span className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
                Recommended sizes (300px / 475px)
              </span>
            </>
          )}
        </div>
        <div className="w-full md:w-1/2 space-y-6">
          <div className="flex flex-col gap-4">
            <label className="font-satoshi text-[15px] leading-5 text-black">
              Product Image*
            </label>
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full">
              <label
                htmlFor="image_1"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555] cursor-pointer"
                // onClick={handleLabelClick}
              >
                Choose file
              </label>
              {/* <input
                id="image_1"
                type="file"
                className="hidden"
                ref={fileInputRef}
                {...register("image_1")}
                onChange={(e) => {
                  const file = e.target.files ? e.target.files[0] : undefined;
                  if (file) {
                    const reader = new FileReader();
                    reader.onloadend = () => {
                      setPreview(reader.result as string);
                      setFileName(file.name);
                      setValue("image_1", file);
                    };
                    reader.readAsDataURL(file);
                  }
                }}
              /> */}
              <input
                type="text"
                disabled
                value={fileName}
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
              {/* {errors.image_1?.message && (
                <p className="mt-2 text-sm text-red-400">
                  {errors.image_1.message}
                </p>
              )} */}
            </div>
          </div>
          <div className="flex flex-col gap-4 text-black">
            <label className="font-satoshi text-[15px] leading-5">Title</label>
            <input
              type="text"
              required
              onChange={handleInputChange}
              name="title"
              defaultValue={newProductFields["title"]}
              aria-required
              className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] outline-none p-3 w-full"
            />
            {/* {errors.title?.message && (
              <p className="mt-2 text-sm text-red-400">
                {errors.title.message}
              </p>
            )} */}
          </div>
          <div className="flex flex-col gap-4 text-black">
            <label className="font-satoshi text-[15px] leading-5">
              Description
            </label>
            <textarea
              required
              name="description"
              onChange={handleInputChange}
              aria-required
              defaultValue={newProductFields["description"]}
              className="rounded-[10px] h-[196px] border-[1.5px] border-[#D9D9D9] p-3 outline-none w-full"
            />
            {/* {errors.description?.message && (
              <p className="mt-2 text-sm text-red-400">
                {errors.description.message}
              </p>
            )} */}
          </div>
        </div>
      </div>
    </form>
  );
};

export default BasicInformation;
// const BasicInformation = () => {
//   return (
//     <form action={BasicInformationAction}>
//       <div>
//         <input type="file" name="image_1" />
//       </div>
//       <div className="flex flex-col gap-4 text-black">
//         <label className="font-satoshi text-[15px] leading-5">Title</label>
//         <input
//           type="text"
//           required
//           name="title"
//           aria-required
//           className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] outline-none p-3 w-full"
//         />
//       </div>
//       <div className="flex flex-col gap-4 text-black">
//         <label className="font-satoshi text-[15px] leading-5">
//           Description
//         </label>
//         <input
//           type="text"
//           required
//           name="description"
//           aria-required
//           className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] outline-none p-3 w-full"
//         />
//       </div>
//       <button className="px-10 py-5 bg-[#fda600] text-white">Continue</button>
//     </form>
//   );
// };
// export default BasicInformation;
