import Image from "next/image";
import React from "react";
import senator from "../../../../public/senator.svg";
import man from "../../../../public/man3_assets.svg";
import man1 from "../../../../public/man4_asset.svg";
import man2 from "../../../../public/man5_asset.svg";
import woman1 from "../../../../public/woman3.svg";
import woman2 from "../../../../public/woman4.svg";
import bg from "../../../../public/bg.svg";
import ceo from "../../../../public/ceo.png";
import girl from "../../../../public/girl.png";

const page = () => {
  return (
    <div className="bg-[#F4F3EC] flex flex-col gap-6 pb-9">
      <section className="flex flex-col gap-6 md:gap-10 md:flex-row py-5 px-1 md:px-20 md:h-[580px] ">
        <div className="w-full md:w-1/2 md:h-full ">
          <Image src={senator} alt="" className="w-full h-full object-cover" />
        </div>
        <div className="gap-3 w-full md:w-1/2 flex flex-col justify-between">
          <div className="flex flex-col items-center md:items-start gap-3">
            <h3 className="font-bon_foyage text-3xl md:text-5xl  leading-tight text-black">
              Welcome to Fashionistar
            </h3>
            <p className="font-satoshi text-sm md:text-[22px] md:leading-[30px] text-center md:text-left text-[#282828] px-1 md:px-0">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet. Ac massa sed ante placerat enim sed
              consequat magna gravida. Enim in platea venenatis volutpat urna
              lorem.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-1 h-[150px] md:h-auto ">
            <div className="w-full h-full">
              <Image src={man} alt="" className="w-full h-full object-cover" />
            </div>
            <div className="w-full h-full">
              <Image src={man1} alt="" className="w-full h-full object-cover" />
            </div>
            <div className="w-full h-full">
              <Image src={man2} alt="" className="w-full h-full object-cover" />
            </div>
          </div>
        </div>
      </section>

      <section className="py-[20px]">
        <div className="relative flex justify-center md:w-1/2 lg:w-1/3 mx-auto items-end">
          <h3 className="font-bon_foyage text-[28px] md:text-[48px] md:leading-[48px] leading-7 text-black">
            What we offer our clients?
          </h3>
          <span className="absolute right-0 -bottom-1">
            <svg
              width="109"
              height="27"
              viewBox="0 0 109 27"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M2.05388 20.0467C5.30093 19.7392 9.10105 17.3538 11.9928 16.156C20.5545 12.6095 29.2501 9.79869 38.2192 7.47424C43.7711 6.03539 49.4216 4.47266 55.1224 3.73394C61.2449 2.94058 67.4698 2.96795 73.6201 2.47231C78.3577 2.09052 83.0442 1.53635 87.8065 1.7031C90.0117 1.78032 93.5 1.59593 95.4766 2.86767C101.423 6.69334 82.9081 15.5977 81.6792 16.2677C77.1841 18.7185 72.6185 20.8725 67.9103 22.8683C66.6731 23.3928 65.5039 23.9322 64.5277 24.8719C64.2927 25.0981 63.6761 25.7412 64.497 25.5453C68.7343 24.5341 72.9516 22.2584 76.9374 20.607C84.277 17.5659 90.8839 15.5536 98.7203 14.6746C101.571 14.3548 104.382 14.6798 107.226 14.9015"
                stroke="#FDA600"
                strokeWidth="2.73129"
                strokeLinecap="round"
              />
            </svg>
          </span>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-fluid py-10 px-2 md:px-20 gap-4 ">
          <div className="hover:bg-[#fda600] transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="35"
              height="36"
              viewBox="0 0 35 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M16.036 15.0835H16.0579M16.0414 23.8335H16.0633"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M10.2083 19.4585H21.8749"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M25.5212 7.79199C26.7294 7.79199 27.7087 8.77137 27.7087 9.97949C27.7087 11.1876 26.7294 12.167 25.5212 12.167C24.3131 12.167 23.3337 11.1876 23.3337 9.97949C23.3337 8.77137 24.3131 7.79199 25.5212 7.79199Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M4.04559 16.7516C2.58267 18.3855 2.5512 20.8505 3.89383 22.5846C6.55813 26.0257 9.47425 28.9418 12.9153 31.606C14.6494 32.9487 17.1144 32.9172 18.7483 31.4544C23.1843 27.4825 27.2466 23.3316 31.1672 18.7699C31.5548 18.319 31.7972 17.7663 31.8516 17.1741C32.0922 14.5555 32.5866 7.01106 30.5378 4.9622C28.4888 2.91335 20.9444 3.40766 18.3258 3.64827C17.7336 3.7027 17.1809 3.94515 16.7298 4.33274C12.1684 8.25325 8.01748 12.3157 4.04559 16.7516Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
            <h3 className="font-bon_foyage text-black text-center  md:text-[32px] md:leading-8 leading-4">
              Best Prices and Offers
            </h3>
            <p className="text-center text-[#282828] text-[9px]  md:text-base md:leading-4 leading-3 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="hover:bg-[#fda600] transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="36"
              height="36"
              viewBox="0 0 36 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M20.1373 6.36597C23.7893 6.36597 26.7495 9.30038 26.7495 12.9202C26.7495 16.5399 23.7893 19.4744 20.1373 19.4744C16.8969 19.4744 14.201 17.1641 13.6345 14.1146"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <path
                d="M32.5794 21.4312H29.0896C28.6609 21.4312 28.2381 21.5277 27.8547 21.713L24.8793 23.1521C24.4959 23.3375 24.0731 23.4339 23.6443 23.4339H22.1251C20.6556 23.4339 19.4643 24.5861 19.4643 26.0074C19.4643 26.0647 19.5037 26.1153 19.5607 26.1311L23.2634 27.1544C23.9277 27.3378 24.6389 27.274 25.2568 26.975L28.4377 25.4369M19.4643 25.0723L12.7716 23.0171C11.5851 22.6475 10.3026 23.0856 9.55934 24.1143C9.02197 24.8581 9.24077 25.9233 10.0237 26.3748L20.9756 32.6905C21.6721 33.0921 22.494 33.1901 23.2601 32.9629L32.5794 30.1989"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M3.41895 7.09092C5.64639 6.2195 8.8156 4.09309 10.548 3.65715C14.3872 2.88626 16.4014 4.02155 20.9479 6.36732C19.0344 6.40786 16.4621 7.50281 15.1961 10.0047M15.1961 10.0047H12.5942M15.1961 10.0047H17.1049C17.679 10.0464 18.9161 10.3922 19.3929 11.5019C19.5842 11.9473 19.6387 12.4765 19.2631 12.7439C18.7566 13.2664 18.0296 13.246 17.3847 13.3603M17.3847 13.3603C16.6446 13.4914 15.9317 13.6371 15.1863 13.7821M17.3847 13.3603L15.1863 13.7821M15.1863 13.7821C15.0218 13.8141 14.8557 13.8461 14.6874 13.8778M15.1863 13.7821L14.6874 13.8778M14.6874 13.8778C13.5255 14.0076 10.6932 15.3625 9.31385 15.742C8.84434 15.9662 5.08037 16.6959 3.43957 16.5678"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>

            <h3 className="font-bon_foyage text-black text-center  md:text-[32px] md:leading-8 leading-4">
              Unique Accurate Measurement
            </h3>
            <p className="text-center text-[#282828] text-[9px] md:text-base md:leading-4 leading-3 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="hover:bg-[#fda600] transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="36"
              height="36"
              viewBox="0 0 36 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M29.159 26.1224C29.159 28.1308 27.5308 29.759 25.5224 29.759C23.514 29.759 21.8859 28.1308 21.8859 26.1224C21.8859 24.114 23.514 22.4858 25.5224 22.4858C27.5308 22.4858 29.159 24.114 29.159 26.1224Z"
                stroke="currentColor"
                strokeWidth="1.49618"
              />
              <path
                d="M14.6131 26.1224C14.6131 28.1308 12.9849 29.759 10.9765 29.759C8.96811 29.759 7.33997 28.1308 7.33997 26.1224C7.33997 24.114 8.96811 22.4858 10.9765 22.4858C12.9849 22.4858 14.6131 24.114 14.6131 26.1224Z"
                stroke="currentColor"
                strokeWidth="1.49618"
              />
              <path
                d="M21.886 26.1223H14.6129M22.6133 23.213V10.8487C22.6133 8.79159 22.6133 7.76301 21.9743 7.12394C21.3352 6.48486 20.3066 6.48486 18.2495 6.48486H8.06711C6.00997 6.48486 4.98139 6.48486 4.34232 7.12394C3.70325 7.76301 3.70325 8.79159 3.70325 10.8487V22.4857C3.70325 23.8452 3.70325 24.5249 3.99557 25.0313C4.18707 25.363 4.46252 25.6385 4.79421 25.8299C5.30054 26.1223 5.98028 26.1223 7.3398 26.1223M23.3407 10.1214H25.961C27.1679 10.1214 27.7713 10.1214 28.2715 10.4046C28.7716 10.6878 29.0822 11.2053 29.703 12.2401L32.1738 16.3581C32.4828 16.8731 32.6373 17.1307 32.7166 17.4165C32.7957 17.7023 32.7957 18.0026 32.7957 18.6033V22.4857C32.7957 23.8452 32.7957 24.5249 32.5033 25.0313C32.3119 25.363 32.0364 25.6385 31.7047 25.8299C31.1984 26.1223 30.5186 26.1223 29.1591 26.1223"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M10.2485 10.8491V16.6673M16.067 10.8491V16.6673"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>

            <h3 className="font-bon_foyage text-black text-center  md:text-[32px] md:leading-8 leading-4">
              Free Delivery
            </h3>
            <p className="text-center text-[#282828] text-[9px] md:text-base md:leading-4 leading-3 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="hover:bg-[#fda600] transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="36"
              height="36"
              viewBox="0 0 36 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M23.3796 23.9073H28.0915C29.9523 23.8759 32.7949 24.8553 32.7949 28.3874C32.7949 32.0523 29.2871 32.6668 28.0915 32.6668C26.896 32.6668 15.6055 32.6668 12.3512 32.6668C8.70588 32.6668 3.70444 31.9284 3.70447 25.6396V12.3076H32.7949V18.8781M23.3796 23.9073C23.3874 23.5962 23.5198 23.2876 23.777 23.0635L26.2525 20.9975M23.3796 23.9073C23.3713 24.2393 23.5048 24.5743 23.7802 24.8127L26.2525 26.8253"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M3.71179 12.2908L5.05227 8.94383C6.14001 6.34271 6.68388 5.04217 7.78628 4.30991C8.88866 3.57764 10.3027 3.57764 13.1309 3.57764H23.3413C26.1695 3.57764 27.5834 3.57764 28.6858 4.30991C29.7883 5.04217 30.332 6.34271 31.4199 8.94383L32.7957 12.296"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
              />
              <path
                d="M18.1953 12.3054V3.57764"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
              />
              <path
                d="M15.2863 18.124H21.1048"
                stroke="currentColor"
                strokeWidth="1.49618"
                strokeLinecap="round"
              />
            </svg>

            <h3 className="font-bon_foyage text-black text-center  md:text-[32px] md:left-8 leading-4">
              Easy Returns
            </h3>
            <p className="text-center text-[#282828] text-[9px] leading-3 md:text-base md:leading-4 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="hover:bg-[#fda600] transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="35"
              height="36"
              viewBox="0 0 35 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M22.6043 19.4583C27.8395 19.4583 32.0835 18.1525 32.0835 16.5417C32.0835 14.9308 27.8395 13.625 22.6043 13.625C17.3691 13.625 13.1251 14.9308 13.1251 16.5417C13.1251 18.1525 17.3691 19.4583 22.6043 19.4583Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M32.0835 23.104C32.0835 24.7149 27.8396 26.0207 22.6043 26.0207C17.369 26.0207 13.1251 24.7149 13.1251 23.104"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M32.0835 16.5415V29.3748C32.0835 31.1467 27.8396 32.5832 22.6043 32.5832C17.369 32.5832 13.1251 31.1467 13.1251 29.3748V16.5415"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M12.3953 9.24984C17.6305 9.24984 21.8745 7.944 21.8745 6.33317C21.8745 4.72234 17.6305 3.4165 12.3953 3.4165C7.16011 3.4165 2.91614 4.72234 2.91614 6.33317C2.91614 7.944 7.16011 9.24984 12.3953 9.24984Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M8.74947 16.5417C5.99058 16.206 3.45559 15.3378 2.91614 13.625M8.74947 23.8333C5.99058 23.4976 3.45559 22.6295 2.91614 20.9167"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <path
                d="M8.74947 31.1252C5.99058 30.7895 3.45559 29.9213 2.91614 28.2085V6.3335"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <path
                d="M21.8751 9.25016V6.3335"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>

            <h3 className="font-bon_foyage text-black text-center leading-4  md:text-[32px] md:leading-8">
              100% Satiisfaction
            </h3>
            <p className="text-center text-[#282828] text-[9px]  md:text-base md:leading-4 leading-3 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
          <div className="hover:bg-[#fda600]   transition-colors max--[393px] duration-300 group flex flex-col gap-3 justify-center items-center border-[0.5px] border-[#fda600] rounded-[5px] h-[222px] md:h-[444px] px-4">
            <svg
              className="text-[#fda600] w-[35px] h-[36px] md:w-[70px]  md:h-[70px] group-hover:text-black transition-colors duration-300"
              width="36"
              height="36"
              viewBox="0 0 36 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M6.33374 16.5415V22.3748C6.33374 27.187 6.33374 29.5932 7.82872 31.0882C9.32369 32.5832 11.7298 32.5832 16.5421 32.5832H19.4587C24.271 32.5832 26.6771 32.5832 28.1721 31.0882C29.6671 29.5932 29.6671 27.187 29.6671 22.3748V16.5415"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M4.87476 13.6252C4.87476 12.5348 4.87476 11.9896 5.16782 11.5835C5.35981 11.3175 5.63596 11.0965 5.96851 10.943C6.47612 10.7085 7.1576 10.7085 8.52059 10.7085H27.4789C28.8419 10.7085 29.5234 10.7085 30.031 10.943C30.3635 11.0965 30.6397 11.3175 30.8316 11.5835C31.1248 11.9896 31.1248 12.5348 31.1248 13.6252C31.1248 14.7155 31.1248 15.2607 30.8316 15.6668C30.6397 15.9328 30.3635 16.1538 30.031 16.3073C29.5234 16.5418 28.8419 16.5418 27.4789 16.5418H8.52059C7.1576 16.5418 6.47612 16.5418 5.96851 16.3073C5.63596 16.1538 5.35981 15.9328 5.16782 15.6668C4.87476 15.2607 4.87476 14.7155 4.87476 13.6252Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M9.25012 6.02067C9.25012 4.58243 10.416 3.4165 11.8543 3.4165H12.3751C15.4817 3.4165 18.0001 5.9349 18.0001 9.0415V10.7082H13.9376C11.3488 10.7082 9.25012 8.6095 9.25012 6.02067Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M26.7501 6.02067C26.7501 4.58243 25.5842 3.4165 24.146 3.4165H23.6251C20.5185 3.4165 18.0001 5.9349 18.0001 9.0415V10.7082H22.0626C24.6514 10.7082 26.7501 8.6095 26.7501 6.02067Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M18.0001 16.5415V32.5832"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>

            <h3 className="font-bon_foyage text-black text-center md:text-[32px] md:leading-8 leading-4">
              Great Daily Deals
            </h3>
            <p className="text-center text-[#282828] text-[9px] md:text-base md:leading-4 leading-3 font-satoshi">
              Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
              consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
              mauris elit fames amet.
            </p>
          </div>
        </div>
      </section>
      <section className="flex flex-col gap-4 md:flex-row-reverse px-2 md:px-20 py-6">
        <div className="flex flex-col gap-3 md:w-1/2">
          <p className="font-satoshi text-[20px] leading-[27px] text-[#fda600]">
            Our Performance
          </p>
          <h4 className="font-bon_foyage text-3xl leading-[30px] text-black">
            Your Partners for E-Commerce Fashion Solution
          </h4>
          <p className="font-satoshi text-[15px] leading-5 text-[#282828]">
            Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
            consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
            mauris elit fames amet. Ac massa sed ante placerat enim sed
            consequat magna gravida. Enim in platea venenatis volutpat urna
            lorem.
          </p>
          <span className="font-satoshi text-[15px] leading-5 text-[#282828]">
            Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
            consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
          </span>
        </div>
        <div className="flex items-center gap-2 md:gap-0 md:w-1/2">
          <div className="md:h-3/4 h-[195px] w-full">
            <Image src={woman1} alt="" className=" h-full w-full" />
          </div>
          <div className="h-[336px] md:h-full w-full">
            <Image src={woman2} alt="" className="w-full h-full" />
          </div>
        </div>
      </section>
      <section className="relative">
        <div>
          <Image src={bg} alt="" className="w-full h-" />
        </div>
        <div className="absolute top-0 left-0 bg-[#fda600]/70 w-full h-full flex items-center justify-around">
          <div className="flex flex-col items-center gap-[2px]">
            <p className="font-satoshi font-bold text-3xl leading-10 text-white">
              3+
            </p>
            <span className="font-bon_foyage text-[11px] text-white text-center">
              Glorious years
            </span>
          </div>
          <div className="flex flex-col items-center gap-[2px]">
            <p className="font-satoshi font-bold text-3xl leading-10 text-white ">
              9+
            </p>
            <span className="font-bon_foyage text-[11px] text-white text-center">
              Happy clients
            </span>
          </div>
          <div className="flex flex-col items-center gap-[2px]">
            <p className="font-satoshi font-bold text-3xl leading-10 text-white">
              15+
            </p>
            <span className="font-bon_foyage text-[11px] text-white">
              Project complete
            </span>
          </div>
          <div className="flex flex-col items-center gap-[2px]">
            <p className="font-satoshi font-bold text-3xl leading-10 text-white">
              6+
            </p>
            <span className="font-bon_foyage text-[11px] text-white">
              Team advisory
            </span>
          </div>
          <div className="flex flex-col items-center gap-[2px]">
            <p className="font-satoshi font-bold text-3xl leading-10 text-white">
              7+
            </p>
            <span className="font-bon_foyage text-[11px] text-white">
              Products sale
            </span>
          </div>
        </div>
      </section>
      <section className="space-y-5 py-6 flex flex-col md:flex-row">
        <div className="w-full md:w-1/2 flex flex-col gap-2 items-center ">
          <h3 className="font-bon_foyage text-3xl leading-[30px] text-black">
            Meet the CEO
          </h3>
          <p className="font-satoshi text-[15px] leading-5 text-center text-[#282828]">
            Lorem ipsum dolor sit amet consectetur. Turpis sed fames sed
            consectetur nec arcu laoreet ipsum. Eget vulputate pharetra at
            mauris elit fames amet. Ac massa sed ante placerat enim sed
            consequat magna gravida. Enim in platea venenatis volutpat urna
            lorem.
          </p>
        </div>
        <div className="w-full md:w-1/2">
          <Image
            src={ceo}
            alt="a picture of the CEO"
            className="w-full h-full object-cover"
          />
        </div>
      </section>
      <section className="bg-[#d9d9d9]/30 flex p-3 relative min-h-[234px]">
        <div className="flex flex-col gap-8">
          <h3 className="font-bon_foyage text-[28px] text-black pr-6 leading-6">
            Stay home and get the best fashion outfit from us
          </h3>
          <p className="font-satoshi text-[10px] leading-[14px] text-black">
            Start your daily shopping with{" "}
            <span className="text-[#fda600]">Fashionistar</span>
          </p>
          <div className="flex w-full max-w-[213px]  box-border ">
            <input
              type="email"
              placeholder="Email address"
              className=" px-1  w-3/4 outline-none placeholder:text-xs text-[#A1A1A1]"
            />

            <button className="bg-[#fda600] px-3 py-1 text-white font-satoshi font-medium text-[7.5px] leading-[10px]">
              Subcribe
            </button>
          </div>
        </div>
        <div className="absolute right-0 top-0">
          <Image src={girl} alt="" className="w-full h-full object-contain" />
        </div>
      </section>
    </div>
  );
};

export default page;
