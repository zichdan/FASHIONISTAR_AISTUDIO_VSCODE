"use client";
import {
  createContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  useContext,
} from "react";
import { NewProductType } from "@/types";
import { FormSchema } from "../utils/schema";
import { NewProductFieldTypes } from "../utils/schemas/addProduct";

const initialValue: NewProductType = {
  image_1: undefined as unknown as File,
  title: "",
  description: "",
  sales_price: "",
  regular_price: "",
  shipping_amount: "1000",
  stock_qty: "",
  tag: "",
  total_price: "2000",
  category: "",
  brands: "",
  image_2: undefined as unknown as File,
  image_3: undefined as unknown as File,
  image_4: undefined as unknown as File,
  video: undefined as unknown as File,
  specification: {
    title: "",
    content: "",
  },
  sizes: {
    size: "",
    price: "",
  },
  colors: {
    name: "",
    image: undefined as unknown as File,
    code: "",
  },
};

type NewProductValueTypes = {
  newProductFields: NewProductType;
  updateNewProductField: (fields: Partial<NewProductFieldTypes>) => void;
  resetLocalStorage: () => void;
};

export const NewProductContext = createContext<NewProductValueTypes | null>(
  null
);

const LOCAL_STORAGE_KEY = "new_product_fields";

const NewProductContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const dataFromStorage =
    typeof window !== "undefined" && localStorage.getItem(LOCAL_STORAGE_KEY);
  const data = dataFromStorage ? JSON.parse(dataFromStorage) : initialValue;
  const [newProductFields, setNewProductFields] =
    useState<NewProductType>(data);

  const saveDataToLocalStorage = (currentDealData: NewProductType) => {
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(currentDealData));
  };

  const updateNewProductField = useCallback(
    (dealDetails: Partial<NewProductFieldTypes>) => {
      setNewProductFields((prevFields) => ({
        ...prevFields,
        ...dealDetails,
      }));
    },
    []
  );

  const resetLocalStorage = () => {
    localStorage.removeItem(LOCAL_STORAGE_KEY);
    setNewProductFields(initialValue);
  };

  useEffect(() => {
    saveDataToLocalStorage(newProductFields);
  }, [newProductFields]);

  const contextValue: NewProductValueTypes = useMemo(
    () => ({
      newProductFields,
      updateNewProductField,
      resetLocalStorage,
    }),
    [newProductFields, updateNewProductField]
  );

  return (
    <NewProductContext.Provider value={contextValue}>
      {children}
    </NewProductContext.Provider>
  );
};

export default NewProductContextProvider;

export function useAddProductContext() {
  const context = useContext(NewProductContext);
  if (context === null) {
    throw new Error(
      "useAddProductContext must be used within a NewProductContextProvider"
    );
  }
  return context;
}
