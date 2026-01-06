import React from "react";
import Link from "next/link";
import man from "../../../../public/man4_asset.svg";
import man2 from "../../../../public/woman3.svg";
import Image from "next/image";
const page = () => {
  const products = [
    {
      id: 1,
      image: man,
      title: "Men Senator",
      email: "Vendor4@email.com",
    },
    {
      id: 2,
      image: man2,
      title: "Men Attire",
      email: "Vendor3@email.com",
    },
    {
      id: 3,
      image: man,
      title: "Men Senator",
      email: "Vendor2@email.com",
    },
    {
      id: 4,
      image: man2,
      title: "Men Attire",
      email: "vendor1@email.com",
    },
  ];
  const productList = products.map((product) => {
    return (
      <div key={product.id} className="lg:w-[24%] md:w-[30%] w-[48%]">
        <div className=" overflow-hidden w-full">
          <Image
            src={product.image}
            alt=""
            className="h-[269px] w-full object-cover hover:scale-105 transition duration-100 ease-in-out"
          />
        </div>

        <div className="">
          <p className="font-bon_foyage text-[26px] leading-[26px] text-black">
            {product.title}
          </p>
          <p className="text-black font-satoshi py-2">{product.email}</p>
          <Link
            href="/"
            className=" bg-[#fda600] px-[18px] py-2 text-white font-medium"
          >
            View details
          </Link>
        </div>
      </div>
    );
  });
  return (
    <div className="space-y-10 bg-inherit">
      <div className="flex flex-wrap items-center justify-between space-y-3">
        <div>
          <h3 className="font-satoshi font-medium text-3xl text-black">
            Sellers
          </h3>
          <p className="font-satoshi text-sm text-[#4E4E4E]">
            Add Vendors to join fashionistar
          </p>
        </div>
        <div className="flex items-center gap-4 ">
          <Link
            href="/dashboard/products"
            className="bg-[#fda600] hover:bg-black flex items-center font-satoshi font-medium text-black hover:text-[#fda600] transition-colors duration-150 grow-0  px-5 py-2.5"
          >
            Create New
          </Link>
        </div>
      </div>
      <div className="w-full bg-white rounded-[20px] min-h-[400px] px-3 py-4 md:p-[30px] space-y-5">
        <div className="flex items-center justify-end gap-3">
          <div className="p-2.5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="show 20"
            >
              <option disabled className="">
                show 20
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
          <div className="p-2.5 rounded-[10px] border-[0.8px] border-[#D9D9D9] text-black bg-[#fff]">
            <select
              id="categories"
              className="w-full outline-none bg-inherit"
              defaultValue="status all"
            >
              <option disabled className="">
                status all
              </option>
              <option defaultValue="" className="">
                Agbada
              </option>
            </select>
          </div>
        </div>
        <div className="flex flex-wrap gap-3">{productList}</div>
      </div>
    </div>
  );
};

export default page;
