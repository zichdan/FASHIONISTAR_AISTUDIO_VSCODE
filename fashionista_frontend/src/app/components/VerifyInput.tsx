"use client";
import React, {
  useState,
  useRef,
  useCallback,
  KeyboardEvent,
  useMemo,
} from "react";

const VerificationInput: React.FC = () => {
  const [values, setValues] = useState<string[]>([]);
  const boxRefs = [
    useRef<HTMLInputElement>(null),
    useRef<HTMLInputElement>(null),
    useRef<HTMLInputElement>(null),
    useRef<HTMLInputElement>(null),
  ];

  const handleInput = useCallback(
    (
      e: React.FormEvent<HTMLInputElement>,
      currentIndex: number,
      nextIndex: number,
      prevIndex: number
    ) => {
      const { value } = e.currentTarget;
      if (
        value.length === 1 &&
        nextIndex < boxRefs.length &&
        boxRefs[nextIndex].current
      ) {
        boxRefs[nextIndex]?.current?.focus();
      }
      setValues((prev) => {
        const newValues = [...prev];
        newValues[currentIndex] = value;
        return newValues;
      });
    },
    [boxRefs]
  );

  const handleKeyDown = useCallback(
    (
      e: KeyboardEvent<HTMLInputElement>,
      currentIndex: number,
      prevIndex: number
    ) => {
      if (
        e.key === "Backspace" &&
        prevIndex >= 0 &&
        prevIndex < boxRefs.length &&
        boxRefs[prevIndex].current &&
        e.currentTarget.value === ""
      ) {
        boxRefs[prevIndex]?.current?.focus();
      }
    },
    [boxRefs]
  );

  const combinedValue = values.join("");

  return (
    <div className="flex justify-between space-x-2 w-full">
      {boxRefs.map((boxRef, index) => (
        <input
          key={index}
          type="text"
          maxLength={1}
          className="w-[120px] h-[80px] text-center text-[32px] font-bold font-satoshi border-[1.5px] border-[#d9d9d9] outline-none rounded-[15px]"
          ref={boxRef}
          value={values[index] || ""}
          onInput={(e) => handleInput(e, index, index + 1, index - 1)}
          onKeyDown={(e) => handleKeyDown(e, index, index - 1)}
        />
      ))}
      <input type="hidden" value={combinedValue} name="otp" />
    </div>
  );
};

export default VerificationInput;
