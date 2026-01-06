import Image from "next/image";
import React from "react";
import empty from "../../../../public/empty.svg";
import Link from "next/link";
import man2 from "../../../../public/man4_asset.svg";

const page = () => {
  const cart_items = [
    {
      image: man2,
      size: "XXL",
      title: "Men Senator",
      price: "$1200.00",
    },

    {
      image: man2,
      size: "XXL",
      title: "Men Senator",
      price: "$1200.00",
    },
  ];
  const cartList = cart_items.map((item, index) => {
    return (
      <div
        key={index}
        className="flex items-center gap-4 py-6 border-b-[1.5px] w-full  md:max-h-[350px] h-fit px-2 border-[#d9d9d9]"
      >
        {/* <div className="md:max-w-[235px] md:max-h-[268px] w-1/2 h-[164px] border border-red-500 "> */}
        <Image
          src={item.image}
          alt={item.title}
          className="w-[144px] h-[164px] md:w-[235px] md:h-[268px] object-cover "
        />
        {/* </div> */}
        <div className="flex flex-col gap-2 md:gap-5 lg:gap-8 h-auto w-full">
          <div className="w-full flex justify-between items-center">
            <p className="font-bon_foyage text-xl md:text-3xl  text-black">
              {item.title}
            </p>

            <span className="font-satoshi font-bold text-xl md:text-3xl text-[#fda600]">
              {item.price}
            </span>
          </div>

          <span className=" font-satoshi font-medium text-lg leading-6 text-[#4E4E4E]">
            {item.size}
          </span>
          <div className="flex items-center gap-3">
            <Link
              href="/chats"
              className="font-satoshi font-bold text-xl text-black bg-[#fda600] px-4 py-2.5 max-w-[119px] w-full flex justify-center items-center"
            >
              Chat
            </Link>
            <Link
              href="/cart?options=customize"
              className="font-satoshi font-bold text-xl text-black bg-[#fda600] px-3 py-2.5 flex justify-center items-center"
            >
              Customize
            </Link>
          </div>
        </div>
      </div>
    );
  });
  return (
    <div className="px-2 md:px-8 lg:px-20 bg-[#F4F3EC] flex flex-col gap-6 pb-6 md:py-6">
      <div className="border-b-[1.5px] border-[#D9D9D9] py-3">
        <h3 className="font-bon_foyage w-1/2 text-[40px] leading-[39.68px] md:text-[90px]  md:leading-[89px] text-black md:w-[380px]">
          Your Cart
        </h3>
      </div>
      {cart_items.length == 0 ? (
        <div>
          <p className="font-satoshi font-medium text-xs text-[#4E4E4E]">
            You have no product in your cart
          </p>
          <div className="flex justify-center py-8 items-center">
            <Image src={empty} alt="" />
          </div>
          <div className="w-full h-[327px] flex flex-col justify-between font-satoshi border-[0.74px] border-[#d9d9d9] p-4">
            <div>
              <p className="font-medium text-[17.69px] leading-6 py-2 border-b-[1.11px] border-[#d9d9d9] text-black">
                Order Summary
              </p>
              <p className="uppercase py-2 font-satoshi font-medium text-xs text-black">
                YOUR CART IS EMPTY
              </p>
            </div>
            <div className="flex justify-center w-full h-11">
              <Link
                href="/"
                className="font-satoshi font-bold text-[15px] text-center flex justify-center items-center leading-5 text-black bg-[#fda600] w-full h-full"
              >
                {" "}
                START SHOPPING
              </Link>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-5 justify-between lg:flex-row">
          <div className="w-full lg:w-1/2 space-y-5 md:space-y-10">
            {cartList}
            <div>
              <textarea
                className="w-full h-[154px] rounded-[10px] border border-[#d9d9d9] bg-[#F4F3EC] p-4 text-[#858585] font-medium outline-none"
                placeholder="Additional description"
              />
            </div>
          </div>
          <div className="border border-[#d9d9d9] rounded-[10px] bg-[#F4F3EC] w-full lg:w-[45%] h-fit p-3 md:p-[30px] space-y-5">
            <p className="font-satoshi font-medium text-2xl text-black border-b border-[#d9d9d9] py-3">
              {" "}
              Order Summary
            </p>
            <div className="space-y-3">
              {cart_items.map((item, index) => (
                <div
                  key={index}
                  className="flex justify-between items-center py-3"
                >
                  <span className="font-satoshi font-medium text-black">
                    {item.title}
                  </span>
                  <span className="font-satoshi font-medium text-black">
                    {item.price}
                  </span>
                </div>
              ))}
              <form className="flex items-center h-[60px] w-full">
                <input
                  type="email"
                  className="h-full w-3/4 placeholder:text-[#a1a1a1] px-3 outline-none border border-[#d9d9d9] font-satoshi bg-inherit"
                  placeholder=" Enter coupon code"
                />
                <button className="h-full w-1/4 px-4 bg-[#20AB2C] text-white font-medium font-satoshi">
                  Apply
                </button>
              </form>
              <div className="flex items-center justify-between px-3 h-[60px] w-full bg-[#d9d9d9]">
                <span className="font-medium font-satoshi text-black">
                  Subtotal
                </span>
                <span className="font-medium font-satoshi text-black">
                  $2400.00
                </span>
              </div>
            </div>
            <div className="flex justify-between items-center py-5 border-b-[1.5px] border-[#d9d9d9]">
              <p className="font-satoshi font-medium text-lg text-black">
                Estimated shipping date
              </p>
              <span className="font-satoshi font-medium text-[#555]">
                Calculated at checkout
              </span>
            </div>
            <div className="flex justify-between items-center py-5 border-b-[1.5px] border-[#d9d9d9]">
              <div>
                <p className="font-satoshi font-medium text-lg text-black">
                  Delivery Changes
                </p>
                <span className="font-satoshi font-medium text-[11px] leading-[15px] text-[#555]">
                  Free delivery for people in lagos state
                </span>
              </div>

              <span className="font-satoshi text-[13px] leading-[18px] text-right font-medium text-[#555]">
                Add your delivery address at <br /> checkout to see delivery
                charges
              </span>
            </div>
            <div className="flex justify-between items-center py-5">
              <span className="font-satoshi font-bold text-black">
                TOTAL COST
              </span>
              <span className="font-satoshi text-xl font-bold text-black">
                $2400.00
              </span>
            </div>
            <button className="flex justify-center items-center bg-[#fda600] h-[60px] w-full text-xl font-bold text-black">
              Place your order
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default page;
