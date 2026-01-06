import React from "react";

const TopBanner = ({ title }: { title: string }) => {
  return (
    <div className="hidden lg:flex items-center justify-between  h-[122px] px-10 bg-white fixed top-0 right-0 w-[75%]">
      <h2 className="font-satoshi font-medium text-2xl text-black ">{title}</h2>
      <div className="flex items-center  md:w-[55%] lg:w-[574px] h-[60px] bg-[#d9d9d9] px-4 gap-6">
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
      <div className="flex items-center gap-4">
        <button className="w-8 h-8 flex justify-center items-center border border-[#282828] rounded-full bg-white">
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M3.86878 8.61825C3.81367 9.66525 3.87702 10.7798 2.9416 11.4813C2.50623 11.8079 2.25 12.3203 2.25 12.8645C2.25 13.6131 2.83635 14.25 3.6 14.25H14.4C15.1637 14.25 15.75 13.6131 15.75 12.8645C15.75 12.3203 15.4938 11.8079 15.0584 11.4813C14.1229 10.7798 14.1863 9.66525 14.1312 8.61825C13.9876 5.88917 11.7329 3.75 9 3.75C6.26713 3.75 4.01241 5.88917 3.86878 8.61825Z"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M7.875 2.34375C7.875 2.96507 8.3787 3.75 9 3.75C9.6213 3.75 10.125 2.96507 10.125 2.34375C10.125 1.72243 9.6213 1.5 9 1.5C8.3787 1.5 7.875 1.72243 7.875 2.34375Z"
              stroke="#282828"
            />
            <path
              d="M11.25 14.25C11.25 15.4927 10.2427 16.5 9 16.5C7.75732 16.5 6.75 15.4927 6.75 14.25"
              stroke="#282828"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <button className="w-8 h-8 flex justify-center items-center border border-[#282828] rounded-full bg-white">
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M1.5 4.5L6.68477 7.43773C8.5962 8.52075 9.4038 8.52075 11.3152 7.43773L16.5 4.5"
              stroke="#282828"
              strokeLinejoin="round"
            />
            <path
              d="M1.51183 10.1067C1.56086 12.4059 1.58537 13.5554 2.43372 14.4071C3.28206 15.2586 4.46275 15.2882 6.82412 15.3476C8.27948 15.3842 9.72053 15.3842 11.1759 15.3476C13.5373 15.2882 14.7179 15.2586 15.5663 14.4071C16.4147 13.5554 16.4392 12.4059 16.4881 10.1067C16.504 9.36743 16.504 8.63258 16.4881 7.8933C16.4392 5.59415 16.4147 4.44457 15.5663 3.593C14.7179 2.74142 13.5373 2.71176 11.1759 2.65243C9.72053 2.61586 8.27947 2.61586 6.82411 2.65242C4.46275 2.71175 3.28206 2.74141 2.43371 3.59299C1.58537 4.44456 1.56085 5.59414 1.51182 7.8933C1.49605 8.63258 1.49606 9.36743 1.51183 10.1067Z"
              stroke="#282828"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <div className="w-[34px] h-[34px] flex justify-center items-center rounded-full bg-[#fda600]">
          <span className="font-medium text-white">G</span>
        </div>
      </div>
    </div>
  );
};

export default TopBanner;
