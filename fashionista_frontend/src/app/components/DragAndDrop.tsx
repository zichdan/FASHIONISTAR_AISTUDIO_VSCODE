"use client";
import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import Image from "next/image";

const DragAndDrop = () => {
  const [preview, setPreview] = useState<string | ArrayBuffer | null>(null);

  const onDrop = useCallback((acceptedFiles: any) => {
    console.log("Files", acceptedFiles);
    const file = new FileReader();

    file.onload = function () {
      setPreview(file.result);
    };

    file.readAsDataURL(acceptedFiles[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      "image/*": [".jpeg", ".jpg", ".png"],
    },
    useFsAccessApi: false,
    onDrop,
    onError: (err) => console.log(err),
  });

  return (
    <div
      className="w-full md:w-[90%] bg-[#E8E8E8] shadow flex flex-col justify-center items-center gap-2 h-[182px]"
      {...getRootProps()}
    >
      <input {...getInputProps()} />
      {preview ? (
        <Image
          src={preview as string}
          alt="Preview"
          className="w-full h-full object-cover"
        />
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
          <p className="font-satoshi font-medium text-black">
            Click to upload or drag and drop
          </p>
          <span className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
            SVG, PNG, JPEG or GIF
          </span>
          <span className="font-satoshi text-[13px] leading-[18px] text-[#4E4E4E]">
            Recommended sizes (300px / 475px)
          </span>
        </>
      )}
    </div>
  );
};

export default DragAndDrop;
