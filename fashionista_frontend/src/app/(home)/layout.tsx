import Image from "next/image";
import Link from "next/link";
import Navbar from "@/app/components/Navbar";
import MobileNavBar from "../components/MobileNavBar";
import Footer from "../components/Footer";
import NewNavbar from "../components/NewNavbar";
import NewFooter from "../components/NewFooter";
import NewMobileNav from "../components/NewMobileNav";

export default function Home({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <>
      <main className="flex min-h-screen pb-10 flex-col md:px-0  bg-[#FFF]">
        <header className="">
          <div className="bg-[#01454a] text-white relative py-4 md:py-6 md:px-10  lg:px-20  md:flex md:flex-wrap-reverse lg:flex-nowrap justify-between items-center text-sm ">
            <div className="hidden md:flex justify-between items-center gap-3  font-raleway font-bold md:w-1/2 lg:w-[25%]">
              <Link href="/about-us">About Us</Link>
              <Link href="#">Wishlist</Link>
              <Link href="#">Tracking Order</Link>
            </div>
            <div className="hidden md:flex justify-end md:w-1/2 lg:w-[30%] lg:order-3 gap-4 ">
              <div className="flex items-center gap-2 text-[#BBBBBB]">
                <svg
                  width="30"
                  height="30"
                  viewBox="0 0 30 30"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M18.75 15C18.75 13.6193 19.8693 12.5 21.25 12.5C24.0114 12.5 26.25 14.7386 26.25 17.5C26.25 20.2614 24.0114 22.5 21.25 22.5C19.8693 22.5 18.75 21.3807 18.75 20V15Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M11.25 15C11.25 13.6193 10.1307 12.5 8.75 12.5C5.98857 12.5 3.75 14.7386 3.75 17.5C3.75 20.2614 5.98857 22.5 8.75 22.5C10.1307 22.5 11.25 21.3807 11.25 20V15Z"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M3.75 17.5V13.75C3.75 7.5368 8.7868 2.5 15 2.5C21.2133 2.5 26.25 7.5368 26.25 13.75V19.8077C26.25 22.3181 26.25 23.5733 25.8095 24.5521C25.3081 25.6661 24.4161 26.5581 23.3021 27.0595C22.3233 27.5 21.0681 27.5 18.5577 27.5H15"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                <div className="flex flex-col">
                  <span className="font-medium md:text-sm leading-[27px] text-[#BBBBBB]">
                    +234 90 0000 000
                  </span>
                  <span className="text-[#BBBBBB] leading-4 text-xs font-medium ">
                    24/7 support center
                  </span>
                </div>
              </div>
              <p>ENG</p> <p>USD</p>{" "}
            </div>
            <div className="font-bon_foyage text-2xl lg:text-3xl text-white lg:order-2 md:w-full  lg:w-1/2 text-center">
              Superb value deals on your choice clothings
            </div>
          </div>

          {/* <div className="md:px-4 lg:px-24 flex justify-between py-8">
            <div className="flex items-center w-1/3">
              <Image src="/logo.svg" alt="logo" width={55} height={54} />
              <h2 className="font-bon_foyage px-3 text-4xl leading-9 text-black">
                Fashionistar
              </h2>
            </div>
            <div className="flex items-center md:w-1/2 lg:w-[740px] bg-[#d9d9d9] px-4 gap-6">
              <span className="block transition-all peer-focus:hidden">
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 18 18"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M13.125 13.125L16.5 16.5"
                    stroke="#282828"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M15 8.25C15 4.52208 11.978 1.5 8.25 1.5C4.52208 1.5 1.5 4.52208 1.5 8.25C1.5 11.978 4.52208 15 8.25 15C11.978 15 15 11.978 15 8.25Z"
                    stroke="#282828"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>

              <input
                type="search"
                placeholder="Search for products"
                className="w-full bg-[#d9d9d9] outline-none focus:outline-none peer"
              />
            </div>
            <div className="flex justify-evenly items-center">
              <div className="px-2 lg:px-4 border-r border-[#d9d9d9]">
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 18 18"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M14.5969 2.99561C12.5857 1.76192 10.8303 2.25908 9.7758 3.05101C9.34335 3.37572 9.1272 3.53807 9 3.53807C8.8728 3.53807 8.65665 3.37572 8.2242 3.05101C7.16971 2.25908 5.41432 1.76192 3.40308 2.99561C0.763552 4.61471 0.16629 9.95618 6.25465 14.4626C7.41429 15.3209 7.9941 15.75 9 15.75C10.0059 15.75 10.5857 15.3209 11.7454 14.4626C17.8337 9.95618 17.2364 4.61471 14.5969 2.99561Z"
                    stroke="black"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <div className="lg:px-4 px-2 border-r border-[#d9d9d9]">
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 18 18"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M6 12H11.4474C14.8131 12 15.325 9.8856 15.9458 6.80181C16.1249 5.91233 16.2144 5.4676 15.9991 5.1713C15.7838 4.875 15.371 4.875 14.5456 4.875H4.5"
                    stroke="#282828"
                    strokeLinecap="round"
                  />
                  <path
                    d="M6 12L4.03405 2.6362C3.86711 1.96844 3.26714 1.5 2.57884 1.5H1.875"
                    stroke="#282828"
                    strokeLinecap="round"
                  />
                  <path
                    d="M6.66 12H6.35143C5.32891 12 4.5 12.8635 4.5 13.9285C4.5 14.1061 4.63815 14.25 4.80857 14.25H13.125"
                    stroke="#282828"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M7.875 16.5C8.49632 16.5 9 15.9963 9 15.375C9 14.7537 8.49632 14.25 7.875 14.25C7.25368 14.25 6.75 14.7537 6.75 15.375C6.75 15.9963 7.25368 16.5 7.875 16.5Z"
                    stroke="#282828"
                  />
                  <path
                    d="M13.125 16.5C13.7463 16.5 14.25 15.9963 14.25 15.375C14.25 14.7537 13.7463 14.25 13.125 14.25C12.5037 14.25 12 14.7537 12 15.375C12 15.9963 12.5037 16.5 13.125 16.5Z"
                    stroke="#282828"
                  />
                </svg>
              </div>
              <div className="flex items-center px-2 lg:px-4 ">
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 18 18"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M4.93318 11.6112C3.8721 12.243 1.09002 13.5331 2.7845 15.1475C3.61223 15.936 4.53412 16.5 5.69315 16.5H12.3068C13.4659 16.5 14.3878 15.936 15.2155 15.1475C16.91 13.5331 14.1279 12.243 13.0668 11.6112C10.5786 10.1296 7.42139 10.1296 4.93318 11.6112Z"
                    stroke="#282828"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M12.375 4.875C12.375 6.73896 10.864 8.25 9 8.25C7.13604 8.25 5.625 6.73896 5.625 4.875C5.625 3.01104 7.13604 1.5 9 1.5C10.864 1.5 12.375 3.01104 12.375 4.875Z"
                    stroke="#282828"
                  />
                </svg>
                <span>Account</span>
              </div>
            </div>
          </div> */}
          {/* <MobileNavBar /> */}
          {/* <Navbar /> */}
          <NewMobileNav />
          <NewNavbar />
        </header>
        <section>{children}</section>
      </main>
      {/* <Footer /> */}
      <NewFooter />
    </>
  );
}
