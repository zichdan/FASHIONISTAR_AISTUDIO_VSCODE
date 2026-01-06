import Image from "next/image";
import { data2 } from "../utils/mock";
import Cads from "../components/Cads";
import Link from "next/link";
import Hero from "../components/Hero";
import ShopByCategory from "../components/ShopByCategory";
import LatestCollection from "../components/LatestCollection";
import { CollectionsProps, PageProps } from "@/types";
import { formatCurrency } from "../utils/formatCurrency";

type DealsProp = CollectionsProps & {
  status: "sold out" | "sales";
  new_price: string;
};
type ReviewProps = {
  id: string;
  image: string;
  text: string;
  rating: number;
  name: string;
};
export default async function Home(props: PageProps) {
  const { searchParams } = props;

  const deals = data2.map((card) => {
    return <Cads data={card} key={card.image} />;
  });
  const get_deals = async () => {
    try {
      const res = await fetch("http://localhost:4000/deals");
      const deals = (await res.json()) as DealsProp[];
      return deals;
    } catch (error) {
      console.log(error);
    }
  };
  const get_reviews = async () => {
    try {
      const res = await fetch("http://localhost:4000/reviews", {
        headers: { "Content-Type": "application/json" },
      });
      const reviews = (await res.json()) as ReviewProps[];
      return reviews;
    } catch (error) {
      console.log(error);
    }
  };
  const new_deals = (await get_deals()) || [];

  const dealList = new_deals.map((deal) => (
    <div
      key={deal.id}
      className="flex flex-col w-[45%]  md:w-[32%] max-w-[300px]"
    >
      <div className="relative ">
        <Image
          src={deal.image}
          className="rounded-[8px] w-full h-[220px] md:h-[350px] object-contain"
          alt=""
          width={500}
          height={500}
        />
        <div className="absolute top-7 left-2 md:top-10 lg:top-3 lg:left-3">
          {deal.status == "sales" ? (
            <p className="w-[83px] h-7 rounded-[5px] flex items-center justify-center uppercase bg-[#fda600] text-white font-semibold font-raleway">
              {deal.status}
            </p>
          ) : (
            <p className="bg-[#848484] py-1 px-4 text-white rounded-[5px] uppercase font-semibold">
              {deal.status}
            </p>
          )}
        </div>
        <span className="absolute bottom-8 md:bottom-10 lg:bottom-4 right-3">
          <svg
            width="25"
            height="25"
            viewBox="0 0 25 25"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M12.5 22.2656L13.0391 23.3063C12.8725 23.3926 12.6876 23.4376 12.5 23.4376C12.3124 23.4376 12.1275 23.3926 11.9609 23.3063L11.9484 23.3L11.9203 23.2844C11.7566 23.1999 11.5951 23.1114 11.4359 23.0188C9.53126 21.9353 7.73455 20.6723 6.07031 19.2469C3.19531 16.7672 0 13.0469 0 8.59375C0 4.43125 3.25937 1.5625 6.64062 1.5625C9.05781 1.5625 11.1766 2.81562 12.5 4.71875C13.8234 2.81562 15.9422 1.5625 18.3594 1.5625C21.7406 1.5625 25 4.43125 25 8.59375C25 13.0469 21.8047 16.7672 18.9297 19.2469C17.1244 20.7912 15.164 22.1443 13.0797 23.2844L13.0516 23.3L13.0422 23.3047H13.0391L12.5 22.2656ZM6.64062 3.90625C4.55312 3.90625 2.34375 5.725 2.34375 8.59375C2.34375 11.9531 4.8125 15.0688 7.60156 17.4719C9.12336 18.7733 10.7633 19.9299 12.5 20.9266C14.2367 19.9299 15.8766 18.7733 17.3984 17.4719C20.1875 15.0688 22.6562 11.9531 22.6562 8.59375C22.6562 5.725 20.4469 3.90625 18.3594 3.90625C16.2141 3.90625 14.2828 5.44687 13.6266 7.74375C13.5575 7.98934 13.41 8.20561 13.2066 8.35965C13.0033 8.5137 12.7551 8.59706 12.5 8.59706C12.2449 8.59706 11.9967 8.5137 11.7934 8.35965C11.59 8.20561 11.4425 7.98934 11.3734 7.74375C10.7172 5.44687 8.78594 3.90625 6.64062 3.90625Z"
              fill="#01454A"
            />
          </svg>
        </span>
      </div>{" "}
      <div className="flex flex-col gap-3">
        <span className="text-[#fda600] text-xl">★★★★★</span>
        <p className="font-raleway font-semibold text-lg md:text-2xl text-black">
          {deal.title}
        </p>
        <div className="flex items-center gap-2">
          <p className="font-raleway font-semibold text-lg md:text-2xl text-black">
            {formatCurrency(deal.new_price)}
          </p>
          <p className="font-raleway font-semibold  md:text-xl line-through text-[#848484]">
            {formatCurrency(deal.price)}
          </p>
        </div>
      </div>
    </div>
  ));
  const reviews = (await get_reviews()) || [];

  const reviewList = reviews.map((review) => (
    <div
      style={{ boxShadow: "0px 4px 25px 0px #0000001A" }}
      key={review.id}
      className="flex flex-col md:flex-row items-center gap-10 py-9 px-10 border border-[#D9D9D9] w-full shrink-0  lg:w-[48%]"
    >
      <Image
        src={review.image}
        alt=""
        width={500}
        height={500}
        className="w-[105px] h-[105px] object-cover"
      />
      <div className="flex flex-col items-center md:items-start gap-2.5">
        <span className="text-[#fda600] text-xl">★★★★★</span>

        <p className="font-raleway text-center md:text-left text-xl text-[#333] flex-none  self-stretch grow-0   w-full">
          {review.text}
        </p>

        <p className="font-raleway font-semibold text-2xl text-black ">
          {review.name}
        </p>
      </div>
    </div>
  ));

  return (
    <div className="flex flex-col gap-5">
      <Hero />
      <div className=" mt-10 md:hidden flex z-30">
        <form className="flex w-full">
          <div className="h-[60px] lg:h-[85px] w-full md:w-1/2 bg-[#F4F5FB] rounded-r-[100px] flex items-center p-1.5 lg:p-3">
            <input
              type="email"
              className="w-2/3 h-full outline-none bg-inherit placeholder:not-italic placeholder:font-raleway placeholder:font-medium placeholder:text-xl placeholder:text-[#333] text-[#333]"
              placeholder="Enter Email Address"
            />

            <button className="w-1/3 lg:min-h-[66px] h-full rounded-r-[100px] bg-[#01454a] text-white shrink-0 text-sm lg:text-xl font-bold font-raleway">
              Join Waitlist
            </button>
          </div>
        </form>
      </div>

      <ShopByCategory />
      <LatestCollection searchParams={searchParams} />
      <div className=" w-full h-[593px] bg-[#fda600] md:h-[746px] relative p-10 md:p-14 lg:p-24 flex flex-col gap-5 md:gap-10 items-center">
        <p className="font-raleway font-semibold text-xl text-black">
          SENATOR OUTFITS
        </p>
        <p className="font-bon_foyage text-[42px] md:text-6xl lg:text-[75px] lg:leading-[74px] leading-[42px] text-center text-black md:w-1/2">
          {" "}
          The New Fashion Collection
        </p>
        <Link
          href="/categories"
          className="px-10 py-3 md:py-5 rounded-[100px] bg-[#01454A] flex text-white font-raleway font-semibold text-xl"
        >
          Shop Now
        </Link>
        <Image
          src="/man.png"
          alt=""
          width={500}
          height={500}
          className="w-[200px] h-[232px] md:w-[370px] md:h-[450px] lg:w-[500px] lg:h-[582px] absolute left-0 md:left-6 bottom-0"
        />
        <Image
          src="/adunni.png"
          alt=""
          width={1000}
          height={1000}
          className="w-[200px] h-[321px] md:w-[350px] md:h-[550px] lg:w-[592px] lg:h-[758px] absolute right-0 bottom-0 object-cover"
        />
      </div>
      <div className="px-5 py-10 md:p-10 lg:p-20 space-y-5 md:space-y-10">
        <div className="flex flex-wrap justify-center md:justify-normal items-center gap-5 lg:gap-20">
          <h3 className="font-bon_foyage whitespace-nowrap text-center text-5xl leading-[48px] text-[#333]">
            {" "}
            Deals of the Week
          </h3>
          <div className="flex justify-center items-center space-x-4 bg-[#01454A] rounded-[8px] max-w-[429px] h-[111px] w-full text-white">
            <div className=" p-4 rounded-lg text-center">
              <span className="block text-[32px] leading-[37px] font-medium text-white">
                10
              </span>
              <span className="text-xl font-medium font-raleway text-white">
                Hours
              </span>
            </div>
            :
            <div className="bg-primary text-primary-foreground p-4 rounded-lg text-center">
              <span className="block text-[32px] leading-[37px] font-medium text-white">
                20
              </span>
              <span className="text-xl font-medium font-raleway text-white">
                Minutes
              </span>
            </div>
            :
            <div className="bg-primary text-primary-foreground p-4 rounded-lg text-center">
              <span className="block text-[32px] leading-[37px] font-medium text-white">
                59
              </span>
              <span className="text-xl font-medium font-raleway text-white">
                Seconds
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center flex-wrap gap-y-2 md:gap-3 lg:gap-6 justify-between">
          {dealList}
        </div>
      </div>
      {/* Reviews section */}

      <div className="px-5 py-10 md:p-10 lg:p-20 space-y-5">
        <h2 className="font-bon_foyage text-5xl text-[#333]">Our Reviews</h2>
        <div className="flex md:flex-wrap items-center lg:p-5 overflow-hidden gap-10 md:gap-3 lg:gap-6 justify-between">
          {reviewList}
        </div>
        <div className="flex items-center gap-3 justify-center">
          <span className="w-[1.5rem] h-[1.5rem] rounded-full bg-[#01454A] border-2 border-[#01454A]" />
          <span className="w-[1.5rem] h-[1.5rem] rounded-full bg-[#D9D9D9]/10 border-2 border-[#01454A]" />
          <span className="w-[1.5rem] h-[1.5rem] rounded-full bg-[#D9D9D9]/10 border-2 border-[#01454A]" />
        </div>
      </div>
    </div>
  );
}
