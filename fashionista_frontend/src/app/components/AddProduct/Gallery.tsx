"use client";
import { NewProductType } from "@/types";
import React, { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
// import { FieldErrors, UseFormRegister, UseFormSetValue } from "react-hook-form";
import { NewProductFieldTypes } from "@/app/utils/schemas/addProduct";
import Image from "next/image";
import { GalleryAction } from "@/app/actions/vendor";
const Gallery = ({
  newProductFields,
  updateNewProductField,
}: {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
}) => {
  const [preview, setPreview] = useState({
    image_2: "",
    image_3: "",
    image_4: "",
  });
  const [fileName, setFileName] = useState({
    image_2: "",
    image_3: "",
    image_4: "",
    video: null,
  });

  // const onDrop = useCallback((acceptedFiles: File[]) => {
  //   const file = acceptedFiles[0];
  //   const reader = new FileReader();

  //   reader.onloadend = () => {
  //     updateNewProductField({ video: file });
  //     console.log(URL.createObjectURL(file));

  //     reader.readAsDataURL(acceptedFiles[0]);
  //   };
  // }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      "image/*": [".jpeg", ".jpg", ".png", ".mp4"],
    },
    useFsAccessApi: false,
    onDrop: useCallback(
      (acceptedFiles: File[]) => {
        const file = acceptedFiles[0];
        const reader = new FileReader();

        reader.onloadend = () => {
          // setPreview((prev) => ({
          //   ...prev,
          //   [name]: reader.result as string,
          // }));
          // setFileName((prev) => ({ ...prev, [name]: file.name }));
          updateNewProductField({ video: file });
        };

        reader.readAsDataURL(file);
      },
      [updateNewProductField]
    ),
    onError: (err) => console.log(err),
  });

  const CreateDropzone = (name: "image_2" | "image_3" | "image_4") => {
    const { getRootProps, getInputProps } = useDropzone({
      onDrop: useCallback(
        (acceptedFiles: File[]) => {
          const file = acceptedFiles[0];
          const reader = new FileReader();

          reader.onloadend = () => {
            setPreview((prev) => ({
              ...prev,
              [name]: reader.result as string,
            }));
            setFileName((prev) => ({ ...prev, [name]: file.name }));
            updateNewProductField({ [name]: file });
          };

          reader.readAsDataURL(file);
        },
        [name]
      ),
      accept: { "image/*": [".jpeg", ".jpg", ".png"] },
    });

    return (
      <div
        className="w-full max-h-[270px] bg-[#F5F5F5] shadow flex flex-col justify-center items-center gap-2"
        {...getRootProps()}
      >
        <input {...getInputProps()} name={name} id={name} />
        {newProductFields[name] ? (
          <div className="max-h-full h-full w-full">
            <Image
              src={URL.createObjectURL(newProductFields[name])}
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
            <p className="font-satoshi font-medium text-black text-[9px] leading-3">
              Click to upload or drag and drop
            </p>
            <span className="font-satoshi text-[7.5px] leading-[10px] text-[#4E4E4E]">
              SVG, PNG, JPEG or GIF
            </span>
            <span className="font-satoshi text-[7.5px] leading-[10px] text-[#4E4E4E]">
              Recommended sizes (300px / 475px)
            </span>
          </>
        )}
      </div>
    );
  };

  return (
    <form action={GalleryAction} id="gallery" className="w-full space-y-10">
      <div className="space-y-2">
        <h2 className="font-satoshi font-medium text-lg leading-6 text-black">
          Gallery
        </h2>
        <p className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
          Upload your product images on your gallery
        </p>
      </div>
      <div className="flex flex-col-reverse md:flex-row gap-6">
        {/* Images section */}
        <div className="w-full md:w-[47%] space-y-3">
          <label className="font-satoshi text-[15px] leading-5 text-black ">
            Product Image*
          </label>
          <div className="flex flex-col gap-4">
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full gap-4">
              <label
                htmlFor="image_2"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
              >
                Choose file
              </label>
              {/* <input
                id="image_2"
                type="file"
                className="hidden"
                name="image_2"
                onChange={handleFileChange}
              /> */}
              <input
                type="text"
                value={fileName?.image_2}
                disabled
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
            </div>
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full gap-4">
              <label
                htmlFor="image_3"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
              >
                Choose file
              </label>
              {/* <input
                id="image_3"
                type="file"
                className="hidden"
                name="image_3"
                onChange={handleFileChange}
              /> */}
              <input
                type="text"
                value={fileName?.image_3}
                disabled
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
            </div>
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full gap-4">
              <label
                htmlFor="image_4"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
              >
                Choose file
              </label>
              {/* <input
                id="image_4"
                type="file"
                className="hidden"
                name="image_4"
                onChange={handleFileChange}
              /> */}
              <input
                type="text"
                value={fileName?.image_4}
                disabled
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
            </div>
          </div>
          {/* {[formData.image_2, formData.image_3, formData.image_4].map(
            (imageName, index) => (
              <div
                key={index}
                className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full gap-4"
              >
                <label
                  htmlFor={imageName.name}
                  className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
                >
                  Choose file
                </label>
                <input
                  id={imageName.name}
                  type="file"
                  className="hidden"
                  name={imageName.name}
                  onChange={handleFileChange}
                />
                <input
                  type="text"
                  //   formData.image_1 ? formData.image_1.name : "No file chosen"
                  placeholder={
                    imageName ? (imageName as File).name : "No file chosen"
                  }
                  disabled
                  className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
                />
              </div>
            )
          )} */}
          <div className="grid grid-cols-2 grid-rows-2 gap-2 h-[270px]">
            {CreateDropzone("image_2")}
            {CreateDropzone("image_3")}
            {CreateDropzone("image_4")}
          </div>
        </div>
        {/* Video section */}
        <div className="w-full md:w-[47%] space-y-6  ">
          <div
            className="w-full order-1 md:order-2 h-[270px]  rounded-[10px] bg-[#F5F5F5] shadow flex flex-col justify-center items-center gap-2"
            // className="w-full max-h-[270px] bg-[#F5F5F5] shadow flex flex-col justify-center items-center gap-2"
            {...getRootProps()}
          >
            <input {...getInputProps()} name="video" id="video" />
            {newProductFields.video ? (
              <div className="max-h-full h-full w-full">
                <video
                  src={URL.createObjectURL(newProductFields?.video)}
                  width={200}
                  height={200}
                  controls
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
                <p className="font-satoshi font-medium text-black text-[9px] leading-3">
                  Click to upload or drag and drop
                </p>
                <span className="font-satoshi text-[7.5px] leading-[10px] text-[#4E4E4E]">
                  SVG, PNG, JPEG or GIF
                </span>
                <span className="font-satoshi text-[7.5px] leading-[10px] text-[#4E4E4E]">
                  Recommended sizes (300px / 475px)
                </span>
              </>
            )}
          </div>
          <div className="order-2 md:order-1 w-full">
            <span className="font-satoshi text-[15px] leading-5 text-black ">
              Product Video*
            </span>
            <div className="rounded-[10px] h-[60px] border-[1.5px] border-[#D9D9D9] flex items-center w-full gap-4">
              <label
                htmlFor="video"
                className="bg-[#d9d9d9] px-2 py-2.5 rounded-s-[10px] h-full grid place-content-center font-medium text-[15px] leading-5 text-[#555555]"
              >
                Choose file
              </label>

              <input
                type="text"
                value={newProductFields?.video?.name || ""}
                disabled
                className="h-full bg-transparent px-2 font-medium text-[15px] leading-5 text-[#555555]"
              />
            </div>
          </div>
        </div>
      </div>
    </form>
  );
};

export default Gallery;
