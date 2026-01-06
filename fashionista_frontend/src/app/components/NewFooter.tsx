import Image from "next/image";
import React from "react";
import logo from "../../../public/logo.svg";
import Link from "next/link";
import flutterwave from "../../../public/fwt.png";
import paystack from "../../../public/pst.png";

const NewFooter = () => {
  return (
    <div
      style={{ boxShadow: "0px 4px 20px 0px #00000026" }}
      className=" bg-white pt-8 md:pt-20"
    >
      <div className="w-full  px-8 md:px-12 lg:px-20 flex flex-col md:flex-row justify-between gap-10 md:gap-0 items-center">
        <div className="w-full md:w-[46%] border-b border-[#D9D9D9D] md:border-none py-8 flex flex-col gap-5 items-center md:items-start">
          <div className="flex items-center gap-2 w-1/2 md:w-fit">
            <Image
              src={logo}
              alt="Fashionistar Logo"
              className="w-10 h-10 md:w-[55px] md:h-[56px]"
            />
            <h2 className="font-bon_foyage text-4xl text-[#333]">
              Fashionistar
            </h2>
          </div>
          <p className="font-raleway text-xl text-[#333] text-center md:text-left max-w-[416px] w-full">
            {" "}
            Step into the world of innovation and style as you embark on
            captivating fashion experience and a journey to explore our
            collections.
          </p>
        </div>
        <div className=" border-b border-[#D9D9D9D]  md:border-none pb-8 w-full md:w-[46%] space-y-5 ">
          <p className="font-raleway text-center md:text-left font-semibold text-2xl leading-10 text-black ">
            SIGN UP FOR EMAILS
          </p>
          <p className="font-raleway text-center md:text-left text-xl text-black">
            {" "}
            Enjoy 15% off* your first order when you sign up to our newsletter
          </p>
          <form className="flex z-30 w-full">
            <div className="h-[60px] lg:h-[85px] w-full lg:w-[85%] bg-[#F4F5FB] rounded-r-[100px] flex items-center p-1.5 lg:p-3">
              <input
                type="email"
                className="w-2/3 h-full outline-none bg-inherit placeholder:not-italic placeholder:font-raleway placeholder:font-medium  placeholder:text-[#333] text-[#333]"
                placeholder="Enter Email Address"
              />

              <button className="w-1/3 lg:min-h-[66px] h-full rounded-r-[100px] bg-[#01454a] text-white shrink-0 text-sm lg:text-xl font-bold font-raleway">
                Join Waitlist
              </button>
            </div>
          </form>
        </div>
      </div>
      <div className="w-full px-8 md:px-20 flex items-center gap-y-8  md:gap-4 flex-wrap justify-between py-8">
        <ul className=" md:order-2">
          <li className="text-black hover:text-[#333] text-lg md:text-xl font-raleway font-medium">
            <Link href="#">Our Story</Link>
          </li>
          <li className="text-black hover:text-[#333] text-lg md:text-xl font-raleway font-medium">
            <Link href="#">Careers</Link>
          </li>
          <li className="text-black hover:text-[#333] text-lg md:text-xl font-raleway font-medium">
            <Link href="#">Influencers</Link>
          </li>
          <li className="text-black hover:text-[#333] text-lg md:text-xl font-raleway font-medium">
            <Link href="#">Join our team</Link>
          </li>
        </ul>

        <ul className="font-raleway text-lg md:w-full lg:max-w-[50%]  md:order-1 text-black max-w-[169px] w-full">
          <li>Tel:(234)23-45-666</li>
          <li>Mon-Fri: 8am – 8pm</li>
          <li>Sat-Sun: 8am – 7pm </li>
        </ul>
        <ul className=" md:order-2 max-w-[50%] w-full md:max-w-fit ">
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Contact Us</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Customer Service</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Find Store</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Shipping and return</Link>
          </li>
        </ul>
        <ul className=" md:order-2 max-w-[50%] w-full md:max-w-fit ">
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Contact Us</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Customer Service</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Find Store</Link>
          </li>
          <li className="text-black hover:text-[#333]  md:text-xl font-raleway font-medium">
            <Link href="#">Shipping and Returns</Link>
          </li>
        </ul>
      </div>
      <div className="flex flex-col md:flex-row gap-8 items-center px-8 md:px-4 lg:px-20 justify-between bg-[#fda600] py-8">
        <p className="font-raleway font-semibold whitespace-nowrap text-xl text-black md:order-2">
          {" "}
          © Fashionistar. All Rights Reserved.
        </p>
        <div className="flex items-center gap-4 md:order-1">
          <a href="/">
            <svg
              width="25"
              height="26"
              viewBox="0 0 25 26"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M17.7083 2.5835H14.5833C13.202 2.5835 11.8772 3.13223 10.9005 4.10898C9.92373 5.08573 9.375 6.41049 9.375 7.79183V10.9168H6.25V15.0835H9.375V23.4168H13.5417V15.0835H16.6667L17.7083 10.9168H13.5417V7.79183C13.5417 7.51556 13.6514 7.25061 13.8468 7.05526C14.0421 6.85991 14.3071 6.75016 14.5833 6.75016H17.7083V2.5835Z"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </a>
          <a href="#">
            <svg
              width="25"
              height="26"
              viewBox="0 0 25 26"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M23.9583 3.63547C23.9583 3.63547 21.8562 4.87714 20.6875 5.22922C20.0601 4.50788 19.2263 3.99661 18.299 3.76456C17.3716 3.53252 16.3953 3.59089 15.5021 3.93178C14.609 4.27267 13.8421 4.87964 13.3051 5.6706C12.7682 6.46155 12.4871 7.39832 12.5 8.35422V9.39589C10.6694 9.44336 8.85545 9.03736 7.21976 8.21406C5.58407 7.39077 4.17737 6.17572 3.12496 4.67714C3.12496 4.67714 -1.04171 14.0521 8.33329 18.2188C6.18801 19.675 3.63241 20.4052 1.04163 20.3021C10.4166 25.5105 21.875 20.3021 21.875 8.32297C21.8743 8.0327 21.8465 7.7445 21.7916 7.45839C22.8541 6.41047 23.9583 3.63547 23.9583 3.63547Z"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </a>
          <a href="#">
            <svg
              width="25"
              height="26"
              viewBox="0 0 25 26"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12.5 17.1668C13.6051 17.1668 14.6649 16.7278 15.4463 15.9464C16.2277 15.165 16.6667 14.1052 16.6667 13.0002C16.6667 11.8951 16.2277 10.8353 15.4463 10.0539C14.6649 9.27248 13.6051 8.8335 12.5 8.8335C11.395 8.8335 10.3352 9.27248 9.55376 10.0539C8.77236 10.8353 8.33337 11.8951 8.33337 13.0002C8.33337 14.1052 8.77236 15.165 9.55376 15.9464C10.3352 16.7278 11.395 17.1668 12.5 17.1668Z"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
              <path
                d="M3.125 17.1667V8.83333C3.125 7.452 3.67373 6.12724 4.65049 5.15049C5.62724 4.17373 6.952 3.625 8.33333 3.625H16.6667C18.048 3.625 19.3728 4.17373 20.3495 5.15049C21.3263 6.12724 21.875 7.452 21.875 8.83333V17.1667C21.875 18.548 21.3263 19.8728 20.3495 20.8495C19.3728 21.8263 18.048 22.375 16.6667 22.375H8.33333C6.952 22.375 5.62724 21.8263 4.65049 20.8495C3.67373 19.8728 3.125 18.548 3.125 17.1667Z"
                stroke="black"
                stroke-width="1.5625"
              />
              <path
                d="M18.2291 7.28102L18.2391 7.27002"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </a>
          <a href="#">
            <svg
              width="25"
              height="26"
              viewBox="0 0 25 26"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M8.3333 15.6043C5.2083 10.9168 9.85622 7.271 13.0208 7.271C16.1854 7.271 18.75 8.99391 18.75 13.0002C18.75 16.1647 16.6666 18.2085 14.5833 18.2085C12.5 18.2085 11.4583 16.1252 11.9791 13.0002M12.5 10.9168L9.37497 22.896"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
              <path
                d="M12.5 23.4168C18.2531 23.4168 22.9166 18.7533 22.9166 13.0002C22.9166 7.24704 18.2531 2.5835 12.5 2.5835C6.74685 2.5835 2.08331 7.24704 2.08331 13.0002C2.08331 18.7533 6.74685 23.4168 12.5 23.4168Z"
                stroke="black"
                stroke-width="1.5625"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </a>
        </div>

        <div className="flex items-center gap-7 md:gap-2 lg:gap-7 md:order-3">
          <Image src={flutterwave} alt="Flutterwave" />
          <Image src={paystack} alt="Paystack" />
        </div>
      </div>
    </div>
  );
};

export default NewFooter;
