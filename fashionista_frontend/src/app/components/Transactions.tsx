"use client";
import React, { useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import OnlyDigitsInput from "./NumberInput";
import Collapsible from "./Collapsible";

interface WithdrawalProp {
  order: string;
  date_and_time: string;
  payment_system: "Bank transfer" | "Card";
  transaction_type: "withdrawal" | "deposit";
  status: "pending" | "paid" | "failed";
  amount: number;
}
const Transactions = () => {
  const [isOpen, setIsOpen] = useState<number | null>(null);
  const withdrawal_history: WithdrawalProp[] = [
    {
      order: "50899065",
      date_and_time: "12.05.24 09.00.09",
      payment_system: "Bank transfer",
      transaction_type: "withdrawal",
      status: "paid",
      amount: 10059,
    },
    {
      order: "34299009",
      date_and_time: "05.07.24 09.00.09",
      payment_system: "Bank transfer",
      transaction_type: "withdrawal",
      status: "paid",
      amount: 10059,
    },
    {
      order: "34299229",
      date_and_time: "30.06.24 12.046.09",
      payment_system: "Bank transfer",
      transaction_type: "withdrawal",
      status: "pending",
      amount: 10059,
    },
    {
      order: "34299339",
      date_and_time: "12.05.24 09.00.09",
      payment_system: "Bank transfer",
      transaction_type: "withdrawal",
      status: "paid",
      amount: 10059,
    },
  ];
  const faq = [
    {
      title: "How to withdraw money from the account?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title: "How long does it take to withdraw money from the wallet?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title: "What’s the minimum withdrawable amount?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title:
        "Is their any fees for withdrawing from the wallet into my bank account?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title:
        "Do i need to provide any documents to make a withdrawal from the wallet?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title: "How long does it take to withdraw money from the wallet?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
    {
      title: "What’s the minimum withdrawable amount?",
      text: " Lorem ipsum dolor sit amet consectetur, adipisicing elit. Unde  consequatur molestiae illo libero possimus blanditiis doloribus consectetur alias id exercitationem dolorum, mollitia inventore assumenda nostrum error natus ab! Placeat, facere.",
    },
  ];
  const withdrawalList = withdrawal_history.map((withdrawal) => {
    return (
      <tr
        key={withdrawal.order}
        className="h-[50px] text-black text-[15px] leading-[21px]"
      >
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.order}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.date_and_time}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.payment_system}
        </td>
        <td className="py-6 px-2 text-center align-middle">
          {withdrawal.transaction_type}
        </td>
        <td className="py-6 px-2 text-center align-middle ">
          <div
            className={`${
              withdrawal.status == "paid"
                ? "bg-[#EDFAF3] text-[#25784A] "
                : "bg-[#FEE8E7] text-[#EA1705]"
            } px-2 py-[5px] rounded-[40px] gap-2.5 flex items-center justify-center text-xs`}
          >
            <div
              className={`${
                withdrawal.status == "paid" ? "bg-[#25784A]" : "bg-[#EA1705]"
              } w-2.5 h-2.5 rounded-full`}
            />
            {withdrawal.status}
          </div>
        </td>
        <td
          className={`${
            withdrawal.status == "paid" ? "text-[#25784A]" : "text-[#EA1705]"
          } font-bold tex-[13px] leading-[17.55px] text-center`}
        >
          {withdrawal.amount}
        </td>
      </tr>
    );
  });

  const faqList = faq.map((question, index) => {
    return (
      <div key={index} className="w-1/2">
        <Collapsible
          text={question.text}
          title={question.title}
          isOpen={isOpen == index}
          onClick={() => setIsOpen(isOpen === index ? null : index)}
        />
      </div>
    );
  });
  const searchParams = useSearchParams();
  const options = searchParams.get("options");
  const delta = 1;
  return (
    <div>
      <nav className="flex justify-between items-center py-8">
        <div className="space-x-5">
          <Link
            href="/wallet"
            className={`${
              !options
                ? "bg-[#fda600] text-black"
                : "bg-[#d9d9d9] text-[#4E4E4E]"
            } px-5 py-2  font-medium rounded-[30px] transition-colors ease-in-out`}
          >
            Withdrawal
          </Link>

          <Link
            href="?options=transactions"
            className={`${
              options == "transactions"
                ? "bg-[#fda600] text-black"
                : "bg-[#d9d9d9] text-[#4E4E4E]"
            } px-5 py-2  font-medium rounded-[30px] transition-colors ease-in-out`}
          >
            Transactions
          </Link>
        </div>
        <Link
          href="?options=faq"
          className={`${
            options == "faq"
              ? "bg-[#fda600] text-black"
              : "bg-[#d9d9d9] text-[#4E4E4E]"
          } px-5 py-2  font-medium rounded-[30px] transition-colors ease-in-out`}
        >
          FAQ
        </Link>
      </nav>
      <div>
        {!options && (
          <motion.div
            initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
          >
            <div className="shadow-card_shadow rounded-[10px] bg-[#fff] p-[30px] space-y-4">
              <h2 className="font-satoshi font-medium text-xltext-black">
                Withdrawal
              </h2>

              <form className="flex flex-wrap gap-10">
                <div className="flex flex-col gap-2 w-full md:w-[48%]">
                  <OnlyDigitsInput title="Amount" name="amount" />
                </div>
                <div className="flex flex-col gap-2 w-full md:w-[48%]">
                  <label className="font-satoshi text-[15px] leading-5 text-[#000]">
                    Payment Method
                  </label>
                  <input
                    type="text"
                    name="shipping_amount"
                    className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
                  />
                </div>
                <div className="flex flex-col gap-2 w-full md:w-[48%]">
                  <label className="font-satoshi text-[15px] leading-5 text-[#000]">
                    Full Name
                  </label>
                  <input
                    type="text"
                    name="shipping_amount"
                    className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
                  />
                </div>
                <div className="flex flex-col gap-2 w-full md:w-[48%]">
                  <label className="font-satoshi text-[15px] leading-5 text-[#000]">
                    Account Name
                  </label>
                  <input
                    type="text"
                    name="shipping_amount"
                    className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
                  />
                </div>
                <div className="flex flex-col gap-2 w-full">
                  <label className="font-satoshi text-[15px] leading-5 text-[#000]">
                    Bank Name
                  </label>
                  <input
                    type="text"
                    name="shipping_amount"
                    className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
                  />
                </div>
                <div className="flex flex-col gap-2 w-full md:w-[48%]">
                  <label className="font-satoshi text-[15px] leading-5 text-[#000]">
                    Account Number
                  </label>
                  <input
                    type="text"
                    name="shipping_amount"
                    className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
                  />
                </div>
                <div className="flex justify-end items-end gap-2 w-full md:w-[48%]">
                  <button className="rounded-[30px] py-4 px-5 bg-[#fda600] h-[60px] w-[40%] font-medium text-black flex justify-center items-center">
                    Confirm
                  </button>
                </div>
              </form>
            </div>
          </motion.div>
        )}
        {options == "transactions" && (
          <motion.div
            initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
          >
            <div className="shadow-card_shadow rounded-[10px] bg-[#fff] p-[30px] min-h-[200px] space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-satoshi font-medium text-xltext-black">
                  Transactions
                </h2>

                <p className="font-satoshi font-medium text-black">
                  All financial history
                </p>
              </div>
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50 rounded-[5px]">
                  <tr>
                    <th className="px-6  py-4 text-lg leading-6 font-medium text-black text-left">
                      Order
                    </th>
                    <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                      Date and time
                    </th>
                    <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                      Payment System
                    </th>
                    <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                      Transaction type
                    </th>
                    <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                      Status
                    </th>
                    <th className="px-6 py-4 text-lg leading-6 font-medium text-black text-center">
                      Amount
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {withdrawalList}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}
        {options == "faq" && (
          <motion.div
            initial={{ x: delta >= 0 ? "50%" : "-50%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
          >
            <div className="shadow-card_shadow rounded-[10px] bg-[#fff] p-[30px] space-y-4">
              <h2 className="font-satoshi font-medium text-xl text-black">
                Frequently Asked Questions
                <div className="flex flex-wrap items-center">{faqList}</div>
              </h2>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default Transactions;
