import Image from "next/image";
import Link from "next/link";
import React from "react";
interface CategoryProp {
  id: number;
  image: string;
  title: string;
}
const ShopByCategory = async () => {
  const getCategories = async () => {
    try {
      const categoryList = await fetch("http://localhost:4000/category", {
        headers: { "Content-Type": "application/json" },
        // cache: "no-cache",
      });
      const data = ((await categoryList.json()) as CategoryProp[]) || [];
      return data;
    } catch (error) {
      console.log(error);
    }
  };

  const data = (await getCategories()) || [];

  const list = data.map((item) => (
    <div
      key={item.id}
      style={{ boxShadow: "0px 4px 20px 0px #0000000D" }}
      className="w-[32%] md:w-[30%] lg:w-[25%] max-w-[250px] bg-white h-[157px] md:h-[262px] py-6 md:px-10 flex flex-col justify-between items-center border border-[#D9D9D9] rounded-[10px]"
    >
      {" "}
      <Image
        src={item.image}
        alt=""
        width={100}
        height={100}
        className="md:w-[150px] md:h-[150px] w-[55px] h-[55px] object-cover"
      />
      <p className="text-center px-5 text-[15px] leading-[17.6px] md:text-xl font-raleway text-black">
        {item.title}
      </p>
    </div>
  ));
  return (
    <div className="px-5 py-10 md:p-10 lg:p-20 space-y-5 md:space-y-10">
      <h2 className="font-bon_foyage text-[30px] text-center md:text-left md:text-5xl text-[#333333]">
        Shop by Category
      </h2>
      <div className="flex items-center flex-wrap gap-y-2 md:gap-3 lg:gap-5 justify-between">
        {list}
      </div>
      <div className="flex items-center justify-center">
        <Link
          href="/categories"
          className="px-10 py-5 rounded-[100px] bg-[#01454A] flex text-white font-raleway font-semibold text-xl"
        >
          More Categories
        </Link>
      </div>
    </div>
  );
};

export default ShopByCategory;
