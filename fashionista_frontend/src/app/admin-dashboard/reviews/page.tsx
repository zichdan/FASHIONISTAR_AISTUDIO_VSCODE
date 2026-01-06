import React from "react";

const page = () => {
  const reviews = [
    {
      id: "#456667",
      product: "Louis Vuitton Bags",
      name: "Romelle’s",
      rating: 5,
      date: "06.06.24, 04:31pm",
    },
    {
      id: "#256660",
      product: "Louis Vuitton Bags",
      name: "Romelle’s",
      rating: 3,
      date: "06.06.24, 04:31pm",
    },
    {
      id: "#356667",
      product: "Louis Vuitton Bags",
      name: "Romelle’s",
      rating: 3,
      date: "06.06.24, 04:31pm",
    },
    {
      id: "##656653",
      product: "Louis Vuitton Bags",
      name: "Romelle’s",
      rating: 1,
      date: "06.06.24, 04:31pm",
    },
    {
      id: "##456699",
      product: "Louis Vuitton Bags",
      name: "Romelle’s",
      rating: 4,
      date: "06.06.24, 04:31pm",
    },
  ];

  const reviewsList = reviews.map((review) => {
    return (
      <tr key={review.id}>
        <td className="font-satoshi font-medium text-black py-5 ">
          {review.id}
        </td>
        <td className="font-satoshi font-medium text-black py-5">
          {review.product}
        </td>
        <td className="font-satoshi font-medium text-black py-5 ">
          {review.name}
        </td>
        <td className="font-satoshi font-medium text-black py-5  flex items-center gap-1">
          {[...Array(review.rating)].map((_, index) => (
            <svg
              key={index}
              width="18"
              height="17"
              viewBox="0 0 18 17"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M9 0L11.0206 6.21885H17.5595L12.2694 10.0623L14.2901 16.2812L9 12.4377L3.70993 16.2812L5.73056 10.0623L0.440492 6.21885H6.97937L9 0Z"
                fill="#FDA600"
              />
            </svg>
          ))}
        </td>

        <td className="font-satoshi font-medium text-black py-5">
          {review.date}
        </td>
        <td className="font-satoshi font-medium text-black py-5 ">
          <button className="bg-[#fda600] px-5 py-2.5 font-medium text-black">
            Details
          </button>
        </td>
        <td className="font-satoshi font-medium text-black py-6">
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M19 13C19.5523 13 20 12.5523 20 12C20 11.4477 19.5523 11 19 11C18.4477 11 18 11.4477 18 12C18 12.5523 18.4477 13 19 13Z"
              stroke="black"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M12 13C12.5523 13 13 12.5523 13 12C13 11.4477 12.5523 11 12 11C11.4477 11 11 11.4477 11 12C11 12.5523 11.4477 13 12 13Z"
              stroke="black"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M5 13C5.5523 13 6 12.5523 6 12C6 11.4477 5.5523 11 5 11C4.4477 11 4 11.4477 4 12C4 12.5523 4.4477 13 5 13Z"
              stroke="black"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </td>
      </tr>
    );
  });
  return (
    <div className="space-y-10 bg-inherit">
      <h3 className="font-satoshi font-medium text-3xl text-black">Reviews</h3>
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
        <table className="min-w-full divide-y divide-gray-200 table-fixed text-black font-satoshi">
          <thead>
            <tr className="font-satoshi font-medium text-[8.5px] md:text-lg md:leading-6 leading-[11px] text-black bg-[#f7f7f7] rounded-[5px]">
              {/* <th className="pl-2 py-4 flex justify-end">
                <div className="w-6 h-6 rounded-md border-[1.5px] border-black" />
                className="px-6 py-5 font-medium text-black uppercase tracking-wider text-center"
              </th> */}
              <th className="p-4 text-left">ID</th>
              <th className="p-4 text-left">Product</th>
              <th className="p-4 text-left">Name</th>
              <th className="p-4 text-left">Rating</th>
              <th className="p-4 text-left">Date</th>
              <th className="p-4 text-left">Action</th>
              {/* <th className="py-3 px-1 text-center">Order Status</th>*/}
              <th className="py-3 px-1 text-center"></th>
            </tr>
          </thead>
          <tbody className="align-top">{reviewsList}</tbody>
        </table>
      </div>
    </div>
  );
};

export default page;
