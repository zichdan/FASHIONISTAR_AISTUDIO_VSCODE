"use client";
import { NewProductType } from "@/types";
import React, { useCallback, useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
import Image from "next/image";

const Color = ({
  newProductFields,
  updateNewProductField,
}: {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
}) => {
  const [preview, setPreview] = useState<string | undefined>(undefined);
  const [fileName, setFileName] = useState<string>("");

  // Load the image preview from local storage on initial render
  useEffect(() => {
    const storedImageData = localStorage.getItem("image_1");
    const parsedImageData = storedImageData
      ? JSON.parse(storedImageData)
      : null;
    if (parsedImageData?.path) {
      setPreview(parsedImageData.path);
      setFileName(parsedImageData.path.split("/").pop() || "No file chosen");
    }
  }, []);

  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();

      reader.onloadend = () => {
        setPreview(reader.result as string);

        updateNewProductField({
          ...newProductFields,
          colors: {
            ...newProductFields.colors,
            image: file,
          },
        });
        setFileName(file.name);

        localStorage.setItem(
          "image_1",
          JSON.stringify({ path: reader.result })
        );
      };

      reader.readAsDataURL(file);
    },
    [newProductFields, updateNewProductField]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      "image/*": [".jpeg", ".jpg", ".png"],
    },
    useFsAccessApi: false,
    onDrop,
    onError: (err) => console.log(err),
  });

  return (
    <div className="flex flex-col gap-8 w-full">
      <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
        Colors
      </h2>

      {/* <div className="flex flex-col md:flex-row gap-6">
        <div className="flex w-full md:w-[47%] gap-4">
          <div className="flex flex-col w-full">
            <label className="capitalize text-[15px] leading-5 text-[#000]">
              Color
            </label>
            <input
              type="text"
              name="name"
              defaultValue={newProductFields.colors.name}
              onChange={(e) =>
                updateNewProductField({
                  ...newProductFields,
                  colors: {
                    ...newProductFields.colors,
                    name: e.target.value,
                  },
                })
              }
              className="rounded-[70px] text-black border-[#D9D9D9] border-[1.5px] w-full h-[60px] outline-none px-3"
            />
          </div>
          <div className="flex flex-col w-full">
            <label className="capitalize text-[15px] leading-5 text-[#000]">
              Code
            </label>
            <input
              type="text"
              name="code"
              defaultValue={newProductFields.colors.code}
              onChange={(e) =>
                updateNewProductField({
                  ...newProductFields,
                  colors: {
                    ...newProductFields.colors,
                    code: e.target.value,
                  },
                })
              }
              className="rounded-[70px] text-black border-[#D9D9D9] border-[1.5px] w-full h-[60px] outline-none px-3"
            />
          </div>
        </div>
        <div className="w-full md:w-[47%] space-y-6">
          <div className="flex flex-col gap-4">
            <label className="font-satoshi text-[15px] leading-5 text-black">
              Image
            </label>
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full">
              <label
                htmlFor="image"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
              >
                Choose file
              </label>

              <input
                type="text"
                disabled
                value={fileName ? fileName : "No file chosen"}
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
            </div>
          </div>

          <div
            className="w-full md:w-1/2 bg-[#F5F5F5] shadow flex flex-col justify-center items-center gap-2 min-h-[471px]"
            {...getRootProps()}
          >
            <input {...getInputProps()} name="image" id="image" />

            {newProductFields.colors.image ? (
              // <div className="max-h-full h-full w-full">
              //   <Image
              //     src={newProductFields.colors.image}
              //     alt="Preview"
              //     width={200}
              //     height={200}
              //     className="w-full h-full object-cover"
              //   />
              // </div>
            <h2>j</h2>
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
                  SVG, PNG, JPEG, or GIF
                </span>
                <span className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
                  Recommended sizes (300px / 475px)
                </span>
              </>
            )}
          </div>
        </div>
      </div> */}
    </div>
  );
};

export default Color;
