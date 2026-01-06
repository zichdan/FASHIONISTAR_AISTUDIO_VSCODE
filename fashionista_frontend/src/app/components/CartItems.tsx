import React, { useState } from "react";
import Modal from "./Modal";
import { Trash, X } from "lucide-react";
import Image from "next/image";

const CartItems = ({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) => {
  const [quantity, setQuantity] = useState(1);
  return (
    <Modal isOpen={isOpen}>
      <div className="bg-white h-screen w-2/3 md:w-1/2 lg:w-1/3 fixed right-0 top-0 px-5 py-10 space-y-8">
        <div className="flex justify-between items-center">
          <p className="font-raleway font-medium text-xl text-black">
            Cart(01)
          </p>

          <button onClick={onClose}>
            <X />
          </button>
        </div>
        <div className="flex items-center justify-between gap-2 md:justify-around max-h-[10rem] md:max-h-[11rem] h-full">
          <Image
            src="/p11.png"
            alt=""
            className="w-1/2 h-auto max-w-[11rem] max-h-[11rem]"
            width={100}
            height={100}
          />
          <div className=" flex flex-col justify-around w-1/2 md:w-1/3 h-full">
            <p className="font-raleway font-semibold md:text-[22px] leading-6 text-black">
              Pink Knitted Sweat Shirt
            </p>
            <div className="flex h-9 items-center justify-between px-5 py-2 font-semibold font-raleway text-xl text-black gap-3 bg-[#d9d9d9] rounded-[5px] max-w-[7rem]">
              <button
                onClick={() => quantity > 1 && setQuantity((prev) => prev - 1)}
              >
                -
              </button>
              <span>{quantity}</span>
              <button onClick={() => setQuantity((prev) => prev + 1)}>+</button>
            </div>
            <p className="font-raleway font-semibold md:text-[22px] leading-6 text-black">
              {" "}
              ₦180,000.00
            </p>
          </div>
          <button>
            <Trash />
          </button>
        </div>
        <div className="flex items-center justify-between md:justify-around">
          <p className="font-raleway font-semibold text-lg md:text-2xl leading-6 text-black">
            Subtotal
          </p>
          <p className="font-raleway font-semibold text-lg md:text-2xl leading-6 text-black">
            {" "}
            ₦180,000.00
          </p>
        </div>
        <div className="flex flex-col items-center gap-5">
          <button className="uppercase font-raleway font-semibold text-[22px] leading-6 text-[#fda600] w-full max-w-[21.5rem] h-[4.5rem] flex items-center justify-center border border-[#fda600] bg-[#fff]">
            View Cart
          </button>
          <button className="uppercase font-raleway font-semibold text-[22px] leading-6 text-[#fff] w-full max-w-[21.5rem] h-[4.5rem] flex items-center justify-center border border-[#fda600] bg-[#fda600]">
            Checkout
          </button>
        </div>
      </div>
    </Modal>
  );
};

export default CartItems;
