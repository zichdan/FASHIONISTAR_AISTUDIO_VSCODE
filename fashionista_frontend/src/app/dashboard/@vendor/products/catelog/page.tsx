import React from "react";
import Link from "next/link";
import man from "../../../../../../public/man3_assets.svg";
import man2 from "../../../../../../public/man4_asset.svg";
import Image from "next/image";
import { deleteProduct } from "@/app/actions/vendor";
import { fetchWithAuth } from "@/app/utils/fetchAuth";

const page = async () => {
  const products = [
    {
      id: 1,
      image: man,
      title: "Men Senator",
      price: "$1200",
      date: "02.07.2024",
      status: "active",
    },
    {
      id: 2,
      image: man2,
      title: "Men Attire",
      price: "$1200",
      date: "02.07.2024",
      status: "active",
    },
  ];
  const vendor_id = "123abc";
  const product_id = "cba321";
  // const fetchedData = await fetchWithAuth(`/vendor/product/${vendor_id}`);

  // const cartList = products.map((product) => (
  //   <tr
  //     key={product.id}
  //     className="text-[8px] leading-[10px] md:text-base border-b-[1.2px] border-[#d9d9d9]"
  //   >
  //     <td className="py-3 md:py-5 ">
  //       <div className="flex items-center gap-1">
  //         <div className="w-[88px] h-[67px]">
  //           <Image
  //             src={product.image}
  //             alt=""
  //             className="w-full h-full max-w-full aspect-video"
  //           />
  //         </div>

  //         <p>{product.title}</p>
  //       </div>
  //     </td>
  //     <td className="py-3 md:py-5 px-3">{product.price}</td>
  //     <td className="py-3 md:py-5 px-3">{product.category}</td>
  //     <td className="py-3 md:py-5 px-3">{product.sizes}</td>
  //     <td>
  //       <button
  //         // onClick={() => deleteProduct(vendor_id, product_id)}
  //         className="text-black hover:text-[#ED141D]"
  //       >
  // <svg
  //   width="20"
  //   height="20"
  //   viewBox="0 0 20 20"
  //   fill="none"
  //   xmlns="http://www.w3.org/2000/svg"
  // >
  //   <path
  //     d="M16.25 4.58301L15.7336 12.9373C15.6016 15.0717 15.5357 16.1389 15.0007 16.9063C14.7361 17.2856 14.3956 17.6058 14.0006 17.8463C13.2017 18.333 12.1325 18.333 9.99392 18.333C7.8526 18.333 6.78192 18.333 5.98254 17.8454C5.58733 17.6044 5.24667 17.2837 4.98223 16.9037C4.4474 16.1352 4.38287 15.0664 4.25384 12.929L3.75 4.58301"
  //     stroke="currentColor"
  //     stroke-linecap="round"
  //   />
  //   <path
  //     d="M2.5 4.58366H17.5M13.3797 4.58366L12.8109 3.4101C12.433 2.63054 12.244 2.24076 11.9181 1.99767C11.8458 1.94374 11.7693 1.89578 11.6892 1.85424C11.3283 1.66699 10.8951 1.66699 10.0287 1.66699C9.14067 1.66699 8.69667 1.66699 8.32973 1.86209C8.24842 1.90533 8.17082 1.95524 8.09774 2.0113C7.76803 2.26424 7.58386 2.66828 7.21551 3.47638L6.71077 4.58366"
  //     stroke="currentColor"
  //     stroke-linecap="round"
  //   />
  //   <path
  //     d="M7.91699 13.75V8.75"
  //     stroke="currentColor"
  //     stroke-linecap="round"
  //   />
  //   <path
  //     d="M12.083 13.75V8.75"
  //     stroke="currentColor"
  //     stroke-linecap="round"
  //   />
  // </svg>
  //       </button>
  //     </td>
  //     <td>
  //       <Link href="" className="text-[#4E4E4E] hover:text-black">
  // <svg
  //   width="20"
  //   height="20"
  //   viewBox="0 0 20 20"
  //   fill="none"
  //   xmlns="http://www.w3.org/2000/svg"
  // >
  //   <path
  //     d="M11.7284 3.2382C12.3494 2.56539 12.6599 2.22899 12.9898 2.03277C13.7859 1.55929 14.7662 1.54457 15.5757 1.99393C15.9111 2.18016 16.2311 2.50709 16.8712 3.16096C17.5112 3.81483 17.8313 4.14176 18.0136 4.48443C18.4535 5.31126 18.4391 6.31265 17.9756 7.12591C17.7835 7.46296 17.4542 7.78014 16.7956 8.41449L8.95916 15.9622C7.71106 17.1644 7.08699 17.7655 6.30704 18.0701C5.52709 18.3747 4.66966 18.3523 2.95479 18.3075L2.72148 18.3014C2.19942 18.2877 1.93838 18.2809 1.78665 18.1087C1.63491 17.9365 1.65563 17.6706 1.69706 17.1388L1.71956 16.8501C1.83617 15.3532 1.89447 14.6049 2.18675 13.9322C2.47903 13.2594 2.98319 12.7132 3.99152 11.6207L11.7284 3.2382Z"
  //     stroke="currentColor"
  //     stroke-linejoin="round"
  //   />
  //   <path
  //     d="M10.833 3.33301L16.6663 9.16634"
  //     stroke="currentColor"
  //     stroke-linejoin="round"
  //   />
  // </svg>
  //       </Link>
  //     </td>
  //   </tr>
  // ));
  const productList = products.map((product) => {
    return (
      <div
        key={product.id}
        className="flex items-center justify-between p-4 lg:p-[30px] border-t border-[#D9D9D9] flex-wrap"
      >
        <input
          type="checkbox"
          className="w-6 h-6 rounded-[6px] hidden md:inline"
        />
        <div className="flex items-center gap-2 w-[80%] md:w-auto">
          <Image
            src={product.image}
            alt=""
            className="w-[75px] h-[88px] object-cover"
          />
          <p className="font-bon_foyage text-[26px] leading-[26px] text-black">
            {product.title}
          </p>
        </div>
        <p className="text-xl font-bold text-black font-satoshi">
          {product.price}
        </p>
        <p className="text-xl font-bold text-black font-satoshi">
          {product.status}
        </p>
        <p className="text-xl font-bold text-black font-satoshi">
          {product.date}
        </p>
        <div className="flex flex-col gap-1">
          <button className="py-2 px-[18px] gap-1 flex justify-center font-medium items-center text-white bg-[#f28705]">
            <svg
              width="20"
              height="20"
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M11.7284 3.2382C12.3494 2.56539 12.6599 2.22899 12.9898 2.03277C13.7859 1.55929 14.7662 1.54457 15.5757 1.99393C15.9111 2.18016 16.2311 2.50709 16.8712 3.16096C17.5112 3.81483 17.8313 4.14176 18.0136 4.48443C18.4535 5.31126 18.4391 6.31265 17.9756 7.12591C17.7835 7.46296 17.4542 7.78014 16.7956 8.41449L8.95916 15.9622C7.71106 17.1644 7.08699 17.7655 6.30704 18.0701C5.52709 18.3747 4.66966 18.3523 2.95479 18.3075L2.72148 18.3014C2.19942 18.2877 1.93838 18.2809 1.78665 18.1087C1.63491 17.9365 1.65563 17.6706 1.69706 17.1388L1.71956 16.8501C1.83617 15.3532 1.89447 14.6049 2.18675 13.9322C2.47903 13.2594 2.98319 12.7132 3.99152 11.6207L11.7284 3.2382Z"
                stroke="currentColor"
                stroke-linejoin="round"
              />
              <path
                d="M10.833 3.33301L16.6663 9.16634"
                stroke="currentColor"
                stroke-linejoin="round"
              />
            </svg>
            Edit
          </button>
          <button className="py-2 px-[18px] gap-1 flex justify-center font-medium items-center text-[#EA1705] bg-[#EA1705]/10">
            <svg
              width="20"
              height="20"
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M16.25 4.58301L15.7336 12.9373C15.6016 15.0717 15.5357 16.1389 15.0007 16.9063C14.7361 17.2856 14.3956 17.6058 14.0006 17.8463C13.2017 18.333 12.1325 18.333 9.99392 18.333C7.8526 18.333 6.78192 18.333 5.98254 17.8454C5.58733 17.6044 5.24667 17.2837 4.98223 16.9037C4.4474 16.1352 4.38287 15.0664 4.25384 12.929L3.75 4.58301"
                stroke="currentColor"
                stroke-linecap="round"
              />
              <path
                d="M2.5 4.58366H17.5M13.3797 4.58366L12.8109 3.4101C12.433 2.63054 12.244 2.24076 11.9181 1.99767C11.8458 1.94374 11.7693 1.89578 11.6892 1.85424C11.3283 1.66699 10.8951 1.66699 10.0287 1.66699C9.14067 1.66699 8.69667 1.66699 8.32973 1.86209C8.24842 1.90533 8.17082 1.95524 8.09774 2.0113C7.76803 2.26424 7.58386 2.66828 7.21551 3.47638L6.71077 4.58366"
                stroke="currentColor"
                stroke-linecap="round"
              />
              <path
                d="M7.91699 13.75V8.75"
                stroke="currentColor"
                stroke-linecap="round"
              />
              <path
                d="M12.083 13.75V8.75"
                stroke="currentColor"
                stroke-linecap="round"
              />
            </svg>
            Delete
          </button>
        </div>
      </div>
    );
  });
  return (
    <div className="">
      <div className="md:w-[100%] lg:w-[75%] h-20 md:h-[122px] fixed top-0 right-0 hidden md:flex justify-between items-center bg-white px-6">
        <div className="flex items-center gap-2 ">
          <Link href="/dashboard">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M4 12H20"
                stroke="black"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M8.99996 17C8.99996 17 4.00001 13.3176 4 12C3.99999 10.6824 9 7 9 7"
                stroke="black"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </Link>
          <h2 className="font-satoshi font-medium text-xl md:text-2xl text-black">
            Catelog
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <button className="font-satoshi font-medium text-sm text-[#858585] hover:text-[#000] p-2">
            Cancel
          </button>
          <button className="bg-[#fda600] hover:bg-black flex items-center font-satoshi font-medium text-black hover:text-[#fda600] transition-colors duration-150 grow-0  px-5 py-2.5">
            Save Changes
          </button>
        </div>
      </div>
      <div className="mt-5 px-2 md:mt-20 lg:mt-[122px] lg:px-[30px] md:px-4 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between space-y-3">
          <div>
            <h3 className="font-satoshi font-medium text-2xl text-black">
              Product Lists
            </h3>
            <p className="font-satoshi text-sm text-[#4E4E4E]">
              Lists of added products
            </p>
          </div>
          <div className="flex items-center gap-4 ">
            <button className="px-5 py-2.5 bg-[#d9d9d9] font-medium text-[#858585] grow-0">
              Import
            </button>
            <button className="px-5 py-2.5 bg-[#d9d9d9] font-medium text-[#858585] grow-0">
              Export
            </button>
            <Link
              href="/dashboard/products"
              className="bg-[#fda600] hover:bg-black flex items-center font-satoshi font-medium text-black hover:text-[#fda600] transition-colors duration-150 grow-0  px-5 py-2.5"
            >
              Create New
            </Link>
          </div>
        </div>
        <div className="w-full min-h-96 bg-white rounded-[10px] shadow-card_shadow">
          <div className="flex flex-col gap-3 md:flex-row md:justify-between items-center py-5 px-4 lg:px-[30px]">
            <div className="flex items-center gap-4 w-full">
              <input
                type="checkbox"
                className=" w-6 h-6 rounded-[6px] hidden md:inline"
              />
              <div className="border-[0.8px] bg-[#f5f5f5] border-[#d9d9d9] rounded-[10px] text-lg font-medium px-5 w-full md:w-[328px] h-16 flex items-center">
                <select
                  id="categories"
                  className="w-full outline-none bg-[#f5f5f5]"
                  defaultValue="All Categories"
                >
                  <option disabled className="">
                    All Categories
                  </option>
                  <option defaultValue="" className="">
                    Agbada
                  </option>
                </select>
              </div>
            </div>
            <div className="flex items-center justify-end gap-4 w-full ">
              <div className="w-full md:w-[156px] bg-[#f5f5f5] border-[0.8px] border-[#d9d9d9] rounded-[10px] h-16 flex items-center">
                <input
                  type="date"
                  className="w-full bg-[#f5f5f5] outline-none text-lg font-medium px-5"
                />
              </div>
              <div className="w-full border-[0.8px] border-[#d9d9d9] bg-[#f5f5f5] rounded-[10px] text-lg font-medium px-5 md:w-[149px] h-16 flex items-center">
                <select
                  className="w-full outline-none bg-[#f5f5f5]"
                  defaultValue="Status"
                >
                  <option disabled className="">
                    Status
                  </option>
                  <option defaultValue="" className="">
                    Agbada
                  </option>
                </select>
              </div>
            </div>
          </div>
          <div className="">{productList}</div>
        </div>
      </div>
    </div>
  );
};

export default page;

{
  /* <table className="min-w-full divide-y divide-gray-200  table-fixed text-black font-satoshi">
            <thead>
              <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-[5px]">
                <th className="py-3 md:py-4 px-2 w-[40%] text-left">Product</th>
                <th className="py-3 md:py-4 px-2 text-left">Price</th>
                <th className="py-3 md:py-4 px-2 text-left">Category</th>
                <th className="py-3 md:py-4 px-2 text-left">Sizes</th>
                <th className="py-3 md:py-4 px-2 text-left"></th>
                <th className="py-3 md:py-4 px-2 text-left"></th>
              </tr>
            </thead>
            <tbody>{cartList}</tbody>
          </table> */
}
