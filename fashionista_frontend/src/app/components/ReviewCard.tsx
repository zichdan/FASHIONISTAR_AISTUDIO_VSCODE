import Image from "next/image";
import React from "react";
interface ReviewProps {
  review: {
    comment: string;
    user: {
      name: string;
      image: string;
      role: string;
    };
  };
}

const ReviewCard = ({ review }: ReviewProps) => {
  return (
    <div className="flex flex-col gap-3">
      <p className="font-satoshi text-[9.15px] leading-[12.35px] md:text-xl  text-[#282828]">
        {review.comment}
      </p>

      <div className=" flex items-center gap-2 md:gap-4">
        <div>
          <Image
            src={review.user.image}
            alt=""
            className="w-[22.42px] h-[22.42px] md:w-[49px] md:h-[49px] rounded-full object-cover"
          />
        </div>
        <div className="flex flex-col gap-1">
          <p className="font-satoshi font-medium text-[7.32px] leading-[9.88px] md:text-base md:leading-6 text-black">
            {review.user.name}
          </p>
          <span className="font-satoshi text-[#282828] text-[7.41px] leading-[8.65px] md:leading-5 md:text-sm">
            {review.user.role}
          </span>
        </div>
      </div>
    </div>
  );
};

export default ReviewCard;
