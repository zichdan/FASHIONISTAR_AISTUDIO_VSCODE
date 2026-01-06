"use client";
import { useState } from "react";

function OnlyDigitsInput({ title, name }: { title: string; name: string }) {
  const [value, setValue] = useState("");

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const inputValue = event.target.value;
    const regex = /^[0-9]*$/;

    if (regex.test(inputValue)) {
      setValue(inputValue);
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <label className="font-satoshi text-[15px] leading-5 text-[#000]">
        {title}
      </label>
      <input
        type="text"
        name={name}
        required
        pattern="^[0-9]+$"
        value={value}
        onChange={handleChange}
        className="border-[1.5px] border-[#D9D9D9] h-[60px] rounded-[70px] w-full px-3 outline-none text-[#000]"
      />
    </div>
  );
}

export default OnlyDigitsInput;
