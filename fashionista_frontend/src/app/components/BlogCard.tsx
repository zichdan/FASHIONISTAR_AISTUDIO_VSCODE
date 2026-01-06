import React from "react";
import Image from "next/image";
import man from "../../../public/man2_asset.svg";

interface blogProps {
  blog: {
    image: string;
    content: string;
    author: string;
    time: string;
    title: string;
  };
}

const BlogCard = ({ blog }: blogProps) => {
  return (
    <div className="w-full h-[450px] rounded-[20px] bg-white px-2 py-3">
      <div className="w-full h-[60%] flex bg-gray-50 rounded-[20px] items-start">
        <Image
          src={blog.image}
          alt=""
          className="w-full h-full aspect-video object-cover bg-top rounded-xl "
        />
      </div>
      <div className="w-full h-[40%] flex flex-col justify-between py-2 bg-white">
        <p className="font-satoshi font-medium text-[13px] leading-[17px] text-[#848484]">
          {blog.time}
        </p>

        <p className="font-satoshi font-medium text-lgleading-6 text-black">
          {" "}
          {blog.title}
        </p>
        <p className="font-satoshi leading-5 text-[#848484]">{blog.content}</p>

        <p className="font-satoshi text-xs text-black uppercase">
          BY {blog.author}
        </p>
      </div>
    </div>
  );
};

export default BlogCard;
