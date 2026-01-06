import React from "react";
import NewProductContextProvider from "@/app/context/addProductContext";

const layout = ({ children }: { children: React.ReactNode }) => {
  return <NewProductContextProvider>{children}</NewProductContextProvider>;
};

export default layout;
