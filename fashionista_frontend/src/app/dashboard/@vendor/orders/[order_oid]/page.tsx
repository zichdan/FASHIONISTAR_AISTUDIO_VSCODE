import Link from "next/link";
import React from "react";
import Image from "next/image";
import { getSingleOrder, orderAcceptReject } from "@/app/utils/libs";

interface OrderProp {
  params: {
    order_oid: string;
  };
}
const page = async ({ params }: OrderProp) => {
  const { order_oid } = params;

  const order = await getSingleOrder(order_oid);
  console.log(order);

  return (
    <div className="space-y-8 pb-20">
      <div className="w-full h-[122px] px-6 flex justify-between mb-20 items-center bg-white">
        <div className="flex items-center gap-2">
          <Link href="/orders">
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
          <h2 className="font-satoshi font-medium text-2xl text-black">
            Order details
          </h2>
        </div>

        <div>
          <button className="font-satoshi font-medium text-black hover:text-white grow-0 py-2 px-4 bg-[#fda600] rounded-[30px] flex items-center gap-1">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M7.35396 18C5.23084 18 4.16928 18 3.41349 17.5468C2.91953 17.2506 2.52158 16.8271 2.26475 16.3242C1.87179 15.5547 1.97742 14.5373 2.18868 12.5025C2.36503 10.8039 2.45321 9.95455 2.88684 9.33081C3.17153 8.92129 3.55659 8.58564 4.00797 8.35353C4.69548 8 5.58164 8 7.35396 8H16.646C18.4184 8 19.3045 8 19.992 8.35353C20.4434 8.58564 20.8285 8.92129 21.1132 9.33081C21.5468 9.95455 21.635 10.8039 21.8113 12.5025C22.0226 14.5373 22.1282 15.5547 21.7352 16.3242C21.4784 16.8271 21.0805 17.2506 20.5865 17.5468C19.8307 18 18.7692 18 16.646 18"
                stroke="currentColor"
              />
              <path
                d="M17 8V6C17 4.11438 17 3.17157 16.4142 2.58579C15.8284 2 14.8856 2 13 2H11C9.11438 2 8.17157 2 7.58579 2.58579C7 3.17157 7 4.11438 7 6V8"
                stroke="currentColor"
                strokeLinejoin="round"
              />
              <path
                d="M13.9887 16H10.0113C9.32602 16 8.98337 16 8.69183 16.1089C8.30311 16.254 7.97026 16.536 7.7462 16.9099C7.57815 17.1904 7.49505 17.5511 7.32884 18.2724C7.06913 19.3995 6.93928 19.963 7.02759 20.4149C7.14535 21.0174 7.51237 21.5274 8.02252 21.7974C8.40513 22 8.94052 22 10.0113 22H13.9887C15.0595 22 15.5949 22 15.9775 21.7974C16.4876 21.5274 16.8547 21.0174 16.9724 20.4149C17.0607 19.963 16.9309 19.3995 16.6712 18.2724C16.505 17.5511 16.4218 17.1904 16.2538 16.9099C16.0297 16.536 15.6969 16.254 15.3082 16.1089C15.0166 16 14.674 16 13.9887 16Z"
                stroke="currentColor"
                strokeLinejoin="round"
              />
              <path
                d="M18 12H18.009"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            Print Invoice
          </button>
        </div>
      </div>

      <div
        className="w-[95%] md:w-10/12 lg:w-9/12 mx-auto bg-white rounded-md md:rounded-[10px] min-h-[400px] px-[30px] py-5 font-satoshi"
        style={{ boxShadow: "0px 0px 12px 0px #D9D9D930" }}
      >
        <div className="border-b-[1.2px] border-[#D9D9D9] py-4 ">
          <p className="font-medium text-lg leading-6 text-black">
            {" "}
            Order ID #0001
          </p>
          <span className="text-[13px] leading-[18px] text-[#858585]">
            Apr 2, 2024
          </span>
          <p className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#25784A]" />
            <span className="font-medium text-sm text-black">Complete</span>
          </p>
        </div>
        <div className="py-[30px] flex justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-[45px] h-[45px] rounded-full bg-[#fda600] flex justify-center items-center">
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z"
                    stroke="black"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M8 15C8.91212 16.2144 10.3643 17 12 17C13.6357 17 15.0879 16.2144 16 15"
                    stroke="black"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M10 9C10 10.1046 9.10457 11 8 11C6.89543 11 6 10.1046 6 9C6 7.89543 6.89543 7 8 7C9.10457 7 10 7.89543 10 9ZM10 9C10.5602 8.43978 11.1643 8 12 8C12.8357 8 13.4398 8.43978 14 9M14 9C14 10.1046 14.8954 11 16 11C17.1046 11 18 10.1046 18 9C18 7.89543 17.1046 7 16 7C14.8954 7 14 7.89543 14 9ZM21 8H17.7324M6.26756 8H3"
                    stroke="black"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <p className="font-medium text-lg leading-6 text black">
                Customer
              </p>
            </div>
            <p className="text-sm text-[#282828]">Full Name : Rapha3l Dev</p>
            <p className="text-sm text-[#282828]">
              Email Address : iamrapha3l@mail.com
            </p>
            <p className="text-sm text-[#282828]">
              Phone Number : (+234) 90 0000 0000
            </p>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-[45px] h-[45px] rounded-full bg-[#fda600] flex justify-center items-center">
                <svg
                  width="23"
                  height="23"
                  viewBox="0 0 23 23"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M16.2554 1.91211V3.82452M11.4744 1.91211V3.82452M6.69336 1.91211V3.82452"
                    stroke="black"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M3.34668 12.4302V8.60539C3.34668 5.90083 3.34668 4.54856 4.18688 3.70836C5.02708 2.86816 6.37935 2.86816 9.08391 2.86816H13.8649C16.5695 2.86816 17.9217 2.86816 18.7619 3.70836C19.6022 4.54856 19.6022 5.90083 19.6022 8.60539V12.4302C19.6022 15.1347 19.6022 16.487 18.7619 17.3272C17.9217 18.1674 16.5695 18.1674 13.8649 18.1674H9.08391C6.37935 18.1674 5.02708 18.1674 4.18688 17.3272C3.34668 16.487 3.34668 15.1347 3.34668 12.4302Z"
                    stroke="black"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M3.34668 15.2988V8.60539C3.34668 5.90083 3.34668 4.54856 4.18688 3.70836C5.02708 2.86816 6.37935 2.86816 9.08391 2.86816H13.8649C16.5695 2.86816 17.9217 2.86816 18.7619 3.70836C19.6022 4.54856 19.6022 5.90083 19.6022 8.60539V15.2988C19.6022 18.0033 19.6022 19.3556 18.7619 20.1958C17.9217 21.036 16.5695 21.036 13.8649 21.036H9.08391C6.37935 21.036 5.02708 21.036 4.18688 20.1958C3.34668 19.3556 3.34668 18.0033 3.34668 15.2988Z"
                    stroke="black"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M7.6499 14.3435H11.4747M7.6499 9.5625H15.2995"
                    stroke="black"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <p className="font-medium text-lg leading-6 text black">
                Order details
              </p>
            </div>
            <div className="text-sm text-[#282828] flex items-center gap-2">
              <span>Payment :</span>
              <p className="flex items-center gap-1 py-[3px] px-2 rounded-[40px] bg-[#EDFAF3]">
                <span className="w-2 h-2 rounded-full bg-[#25784A]" />
                <span className="font-medium text-sm text-black">Paid</span>
              </p>
            </div>
            <p className="text-sm text-[#282828]">
              Delivery : Deliver before Apr 4, 2024
            </p>
          </div>
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-[45px] h-[45px] rounded-full bg-[#fda600] flex justify-center items-center">
                <svg
                  width="23"
                  height="23"
                  viewBox="0 0 23 23"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M18.6463 16.7333C18.6463 18.0535 17.576 19.1238 16.2557 19.1238C14.9355 19.1238 13.8652 18.0535 13.8652 16.7333C13.8652 15.4131 14.9355 14.3428 16.2557 14.3428C17.576 14.3428 18.6463 15.4131 18.6463 16.7333Z"
                    stroke="black"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M9.08424 16.7333C9.08424 18.0535 8.01397 19.1238 6.69373 19.1238C5.37349 19.1238 4.30322 18.0535 4.30322 16.7333C4.30322 15.4131 5.37349 14.3428 6.69373 14.3428C8.01397 14.3428 9.08424 15.4131 9.08424 16.7333Z"
                    stroke="black"
                    strokeWidth="1.43431"
                  />
                  <path
                    d="M13.8652 16.734H9.08413M18.6462 16.734H19.376C19.5862 16.734 19.6914 16.734 19.7798 16.723C20.4313 16.6418 20.9445 16.1286 21.0257 15.477C21.0367 15.3887 21.0367 15.2835 21.0367 15.0732V12.431C21.0367 8.9984 18.254 6.21571 14.8214 6.21571M14.3433 14.8215V6.69381C14.3433 5.34153 14.3433 4.66539 13.9232 4.24529C13.503 3.8252 12.8269 3.8252 11.4746 3.8252H4.78121C3.42894 3.8252 2.7528 3.8252 2.3327 4.24529C1.9126 4.66539 1.9126 5.34153 1.9126 6.69381V14.3434C1.9126 15.2371 1.9126 15.6839 2.10476 16.0168C2.23064 16.2348 2.41171 16.4159 2.62975 16.5418C2.96259 16.734 3.40942 16.734 4.30311 16.734"
                    stroke="black"
                    strokeWidth="1.43431"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <p className="font-medium text-lg leading-6 text black">
                Delivery
              </p>
            </div>
            <p className="text-sm text-[#282828]">City : Lagos state</p>
            <p className="text-sm text-[#282828]">Area : Surulere</p>
            <p className="text-sm text-[#282828]">Address : 312 W Festac rd.</p>
          </div>
        </div>
        <div>
          <table className="min-w-full divide-y divide-gray-200  table-fixed text-black font-satoshi">
            <thead>
              <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-[5px]">
                <th className="py-4 px-2 w-[40%] text-left">Product</th>
                <th className="py-4 px-2 text-left">Price</th>
                <th className="py-4 px-2 text-left">Quantity</th>
                <th className="py-4 px-2 text-left">Total</th>
              </tr>
            </thead>
            <tbody>
              <tr key={order.id} className=" border-b-[1.2px] border-[#d9d9d9]">
                <td className="py-5 px-1">
                  <div className="flex items-center gap-1">
                    <Image
                      src={order.image}
                      alt=""
                      className="w-[88px] h-[67px]"
                    />
                    <p>{order.title}</p>
                  </div>
                </td>
                <td className="py-5 px-3">{order.price}</td>
                <td className="py-5 px-3">{order.quantity}</td>
                <td className="py-5 px-3">{order.total}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="flex flex-col items-end">
          <div className="w-1/2 md:w-[30%] flex justify-between py-3">
            <span className="font-medium text-black">Amount</span>
            <span className="font-bold text-black">$1200</span>
          </div>
          <div className="w-1/2 md:w-[30%] flex justify-between py-3 border-b-[1.2px] border-[#D9D9D9]">
            <span className=" text-[#585858]">Delivery Fee</span>
            <span className="font-bold text-black">$50</span>
          </div>
          <div className="w-1/2 md:w-[30%] flex justify-between py-3">
            <span className="font-medium text-black">Total</span>
            <span className="font-bold text-black">$1250</span>
          </div>
        </div>
      </div>
      <div className="flex items-center justify-end gap-8 w-9/12 mx-auto">
        <button
          onClick={async () =>
            await orderAcceptReject(order_oid, {
              notification_type: "order-rejected",
            })
          }
          className="font-medium text-lg leading-6 text-[#ED141D]"
        >
          Cancel Order
        </button>

        <button
          onClick={async () =>
            await orderAcceptReject(order_oid, {
              notification_type: "order-accepted",
            })
          }
          className="py-2 px-5 bg-[#fda600] outline-none font-medium text-black grow-0"
        >
          Accept Order
        </button>
      </div>
    </div>
  );
};

export default page;
