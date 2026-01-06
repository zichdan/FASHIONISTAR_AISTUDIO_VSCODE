import TopBanner from "@/app/components/TopBanner";
import Link from "next/link";
import React from "react";
import Transactions from "@/app/components/Transactions";
import { Suspense } from "react";

const page = () => {
  return (
    <div className="space-y-10 px-6 pb-10">
      <TopBanner title="Wallet" />
      <div className="flex items-center justify-between flex-wrap font-satoshi ">
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                xmlnsXlink="http://www.w3.org/1999/xlink"
              >
                <rect width="27" height="27" fill="url(#pattern0_301_1986)" />
                <defs>
                  <pattern
                    id="pattern0_301_1986"
                    patternContentUnits="objectBoundingBox"
                    width="1"
                    height="1"
                  >
                    <use
                      xlinkHref="#image0_301_1986"
                      transform="scale(0.0104167)"
                    />
                  </pattern>
                  <image
                    id="image0_301_1986"
                    width="96"
                    height="96"
                    xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAAACXBIWXMAAAsTAAALEwEAmpwYAAAFcklEQVR4nO2dW4iVVRTHt2lWWpA6YFImmIWU0o0SwijIsMjyJQkinMpCoXqJkXqxAXO6CGUFSUWKEoQEZuFk2UPiGJVENENNU9FEFGTTzDg5XbQ5Nb/YuAcOp3P2dy77ss45+we+jN8333+ttb/LXnutPUolEolEIlEHAC3AWqAT6AVGzb9e8zP9fy2xdTYcwEzgRSBHNjlz7MzYuhsC4CZgiMoZBJbH1l/XAHcCY1U4P/9uuDe2HeIALgLeBH4jPlrDbuBC1UTOH0YeQ8AC1eiY0SaVN1SjI+SxU4qjqtEBRpDLsGp0zIRJKp2q0QHuQS6tqtEBzgb+Rh5jTTN7Bt5FHp2qWdCzU+TRqposuXYcOfwFzFDNBHB3lUk21+ik3erY/kgkEolEIpFIJBIJ7wALgf2xZ2FGw8KmCTkwBXhEWCpiDHgKmKqaYNT3IJeehr0bgJXC14Mn+B24QzXYI0ff3uPUFy/X/SPJpJ27qF+66naVDJhrqpZDvECPePz92oa5qp4A5gM/4p9+4FxzzTUer6Ntma/qAWAe8ANhaC+49oDHa2mb5inJAHPMqAxFW8H1fV9b//45SiLAGcAnhKWtQEOI4H8GnKkkAZwC7CE8bQU6Qt197wCTlRSATYRjCHgWuBk4q0DHdcCWQPWnm5QEgGXAv4E+N58EppWhaYaZSPlE27wsjJdLGzrb8zf4BH/oXrEq9K31PAPXts/2411ZzRYratDY7lnbbrdeLd+wFYRhu4NcVI/UAVKtUdMDTbZytjQAcCpwI3B5ht5bPevUvpjuxdklDNpIGA5klLl/kXfsloy74BfPWjd6c3iRDOcxwvC4Rcf6Isdfazl+h2etx4JkToEOwrHaomNvkeNfsRzv+7NU0+HN8caIWWZzjFCstGg5XGIU/i9NoBdWAr2ztG9m+QxAsdveJ7dbtBwocc6e/Beicf6rATWv9xmAPsJyn0XL05bzfga2mV1Tvicsfb6cv5TwbLboOT/gx0ClLPURgO0RDPkoQ9Ny014kjZomj8UMnRxpg41xvblHhrYLgIPI4qjTdDWwRPJo4uQAedD0e0lhicsAbIhoyLhOJZSpU8+OnylzazPfbHAZgEORjfmzktw7cCXQHVnzIVfOn1rjtmGuyAGPAadXoNt3+sHGmJPKOmARsvgOuK1M7ZOAnRG1LnIRgFXI5GOdii5D/2nAV5E0rnIRAN8rSrWiV+XOKWPryxi0uwjALuQzDFyT8Sj6NoKuXS4CUC/VzUO2BXLghQiaulwEIPbn3DjwdZnFvk9Y7LiL8HS7CEDIWs9CDuenIoCrgW8ozacWO/TacWj6XQRgMOJzvaWIngWWme5PFjt08EIz6CIAJ4jDtgqXIzW9lnN02WJoTrgIQKy8ynMWTa0lztmZsRF4aHIuAqC7BmPweUY9kC4Tz0f3HV9qOWdzBBtGXQTAZ9dJFoszymN0se4HwGvAFRl2hOhXK+SIiwDEbKzeUbMBJ224IZL+7nrf43McuL5G/dMizYI1+1wE4HniMgBcXKV2/a54PaL2kuWSlRhxP/EZAG6pondhX2Tda1wEYDEyGAfe1o8k3ZNm0XueyeBK2JfiEhcB0JnEX5HFMPBWkZSzLU0RGu2zSTUHwBj3EvIYKdC4DllsdeJ8Y9xVyGNEeACs85JqgvAhsjie/y4AHkYOB5063xh4GfAPsliX15Yae91igpxtBl9rEPTGSwiskhhFDh2NuCVBvbDX+xYGpkPy/diWCuS9crr4XQVhitBP01hs1T4J4vwi/behO1Ak0R+8SbvEPkEPRcq3x+JL4AFtu5KE6SN41Py1vD5h9frVMmhs6TQ7/rqr+08kEolEIpFIJBKqGfkPOnX6XLgWF3IAAAAASUVORK5CYII="
                  />
                </defs>
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Total Amount</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              $180,050
            </p>
          </div>
        </div>
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M16.875 8.4375C16.875 8.4375 17.4375 8.4375 18 9.5625C18 9.5625 19.7867 6.75 21.375 6.1875"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M24.75 7.875C24.75 10.9816 22.2316 13.5 19.125 13.5C16.0184 13.5 13.5 10.9816 13.5 7.875C13.5 4.7684 16.0184 2.25 19.125 2.25C22.2316 2.25 24.75 4.7684 24.75 7.875Z"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                />
                <path
                  d="M25.5937 14.8997C25.593 14.4336 25.2145 14.0565 24.7485 14.0574C24.2826 14.0582 23.9055 14.4366 23.9062 14.9026L25.5937 14.8997ZM10.199 7.59667C10.665 7.59403 11.0406 7.21414 11.038 6.74816C11.0354 6.28218 10.6555 5.90656 10.1895 5.90919L10.199 7.59667ZM15.1875 23.9063H11.8125V25.5938H15.1875V23.9063ZM11.8125 23.9063C9.6785 23.9063 8.14897 23.9051 6.97382 23.7723C5.81418 23.6413 5.11154 23.3919 4.58133 22.9731L3.53546 24.2975C4.41675 24.9935 5.47697 25.3014 6.7844 25.4492C8.07633 25.5951 9.71811 25.5938 11.8125 25.5938V23.9063ZM1.40625 15.7501C1.40625 17.7176 1.40464 19.2732 1.56107 20.5001C1.72049 21.75 2.05516 22.769 2.8046 23.6096L4.0642 22.4866C3.62924 21.9987 3.37172 21.3584 3.23503 20.2865C3.09536 19.1913 3.09375 17.7623 3.09375 15.7501H1.40625ZM4.58133 22.9731C4.39363 22.825 4.22066 22.6621 4.0642 22.4866L2.8046 23.6096C3.02702 23.8591 3.27162 24.0891 3.53546 24.2975L4.58133 22.9731ZM23.9062 15.7501C23.9062 17.7623 23.9047 19.1913 23.7649 20.2865C23.6283 21.3584 23.3707 21.9987 22.9358 22.4866L24.1954 23.6096C24.9448 22.769 25.2795 21.75 25.4389 20.5001C25.5953 19.2732 25.5937 17.7176 25.5937 15.7501H23.9062ZM15.1875 25.5938C17.2819 25.5938 18.9236 25.5951 20.2156 25.4492C21.523 25.3014 22.5832 24.9935 23.4646 24.2975L22.4187 22.9731C21.8884 23.3919 21.1858 23.6413 20.0261 23.7723C18.8511 23.9051 17.3215 23.9063 15.1875 23.9063V25.5938ZM22.9358 22.4866C22.7793 22.6621 22.6064 22.825 22.4187 22.9731L23.4646 24.2975C23.7284 24.0891 23.973 23.8591 24.1954 23.6096L22.9358 22.4866ZM3.09375 15.7501C3.09375 13.7379 3.09536 12.3088 3.23503 11.2136C3.37172 10.1417 3.62924 9.50145 4.0642 9.01358L2.8046 7.89061C2.05516 8.73122 1.72049 9.75011 1.56107 11.0002C1.40464 12.2269 1.40625 13.7826 1.40625 15.7501H3.09375ZM3.53546 7.20265C3.27162 7.41101 3.02702 7.64114 2.8046 7.89061L4.0642 9.01358C4.22066 8.83808 4.39363 8.6752 4.58133 8.52698L3.53546 7.20265ZM25.5937 15.7501C25.5937 15.4585 25.5942 15.1731 25.5937 14.8997L23.9062 14.9026C23.9067 15.1742 23.9062 15.4544 23.9062 15.7501H25.5937ZM10.1895 5.90919C8.606 5.91816 7.31712 5.95463 6.26128 6.12126C5.18964 6.29039 4.29595 6.60206 3.53546 7.20265L4.58133 8.52698C5.03951 8.16513 5.62639 7.92984 6.52435 7.78813C7.43809 7.64392 8.60781 7.60567 10.199 7.59667L10.1895 5.90919Z"
                  fill="white"
                />
                <path
                  d="M11.25 20.25H12.9375"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M16.3125 20.25H20.25"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-miterlimit="10"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M2.8125 12.375H11.25"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">
              Withdrawable Amount
            </p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              $42,500
            </p>
          </div>
        </div>
        <div className="w-[32%] h-[170px] rounded-[10px] bg-[#fff] shadow-card_shadow p-5 flex flex-col justify-between">
          <div className="flex items-center gap-4">
            <div className="flex justify-center items-center bg-black w-[45px] h-[45px] rounded-full">
              <svg
                width="27"
                height="27"
                viewBox="0 0 27 27"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M19.125 2.25V4.5M13.5 2.25V4.5M7.875 2.25V4.5"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M3.9375 14.625V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V14.625C23.0625 17.8069 23.0625 19.3979 22.074 20.3865C21.0854 21.375 19.4944 21.375 16.3125 21.375H10.6875C7.50552 21.375 5.91453 21.375 4.92602 20.3865C3.9375 19.3979 3.9375 17.8069 3.9375 14.625Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
                <path
                  d="M3.9375 18V10.125C3.9375 6.94302 3.9375 5.35203 4.92602 4.36351C5.91453 3.375 7.50552 3.375 10.6875 3.375H16.3125C19.4944 3.375 21.0854 3.375 22.074 4.36351C23.0625 5.35203 23.0625 6.94302 23.0625 10.125V18C23.0625 21.1819 23.0625 22.7729 22.074 23.7615C21.0854 24.75 19.4944 24.75 16.3125 24.75H10.6875C7.50552 24.75 5.91453 24.75 4.92602 23.7615C3.9375 22.7729 3.9375 21.1819 3.9375 18Z"
                  stroke="white"
                  stroke-width="1.43431"
                />
                <path
                  d="M9 16.875H13.5M9 11.25H18"
                  stroke="white"
                  stroke-width="1.43431"
                  stroke-linecap="round"
                />
              </svg>
            </div>
            <p className="font-satoshi text-xl text-black">Commision</p>
          </div>
          <div className="flex items-center justify-between">
            <p className="font-medium text-[40px] laeding-[54px] text-black">
              $10.92
            </p>
          </div>
        </div>
      </div>
      <Suspense fallback={<div>Loading...</div>}>
        <Transactions />
      </Suspense>
    </div>
  );
};

export default page;
