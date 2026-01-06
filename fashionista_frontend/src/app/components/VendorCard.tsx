import Image from "next/image";
import Link from "next/link";
import React from "react";
import { VendorProp } from "@/types";
interface VendorCardProp {
  vendorProp: VendorProp;
}
const VendorCard = ({ vendorProp }: VendorCardProp) => {
  return (
    <div className="w-[48%] md:w-[30%] lg:w-[290px] flex flex-col gap-3">
      <div className="w-full h-[217px] md:h-[320px]">
        <Image
          src={vendorProp.image}
          alt={vendorProp.name}
          className="w-full h-full object-cover"
          width={500}
          height={500}
        />
      </div>
      <p className="font-bon_foyage text-[19px] leading-5 text-black">
        {vendorProp.name}
      </p>
      <div className="flex items-center">
        <svg
          width="17"
          height="17"
          viewBox="0 0 17 17"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M9.8835 2.46912L11.0644 4.85048C11.2255 5.18198 11.6549 5.49994 12.0173 5.56082L14.1576 5.91938C15.5265 6.1494 15.8486 7.15066 14.8622 8.13838L13.1982 9.81615C12.9163 10.1003 12.7621 10.6483 12.8492 11.0407L13.3257 13.1176C13.7014 14.7615 12.8358 15.3975 11.3932 14.5383L9.38699 13.3409C9.02469 13.1244 8.42752 13.1244 8.05844 13.3409L6.05225 14.5383C4.61635 15.3975 3.74408 14.7548 4.11983 13.1176L4.59622 11.0407C4.68345 10.6483 4.52912 10.1003 4.24731 9.81615L2.58329 8.13838C1.60366 7.15066 1.91902 6.1494 3.28781 5.91938L5.42823 5.56082C5.78385 5.49994 6.21328 5.18198 6.37431 4.85048L7.55522 2.46912C8.19936 1.17696 9.24607 1.17696 9.8835 2.46912Z"
            fill="#FDA600"
          />
        </svg>
        <p className="font-satoshi text-[9.3px] leading-[13px] text-[#4e4e4e]">
          {vendorProp.rating}
        </p>
      </div>
      <p className="font-satoshi text-xs leading-[14px] text-black">
        <span className="font-medium">Address:</span>
        {vendorProp.address}
      </p>
      <p className="font-satoshi text-xs leading-[14px] text-black">
        <span className="font-medium">Call us on:</span>
        {vendorProp.mobile}
      </p>
      <Link
        href={`/vendor/${vendorProp.slug}`}
        className="w-[106.5px] h-[37px] flex justify-center items-center text-white bg-[#fda600] font-medium  text-xs leading-4"
      >
        View Store
      </Link>
    </div>
  );
};

export default VendorCard;
