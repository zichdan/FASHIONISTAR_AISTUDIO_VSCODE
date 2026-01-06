"use server";

import { redirect } from "next/navigation";
import { axiosInstance } from "../utils/axiosInstance";
import { cookies } from "next/headers";
import { signupSchema } from "../utils/schemas/auth_shema";

export const signUp = async (prev: any, formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());

  const validated = signupSchema.safeParse(data);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }

  try {
    const signin = await axiosInstance.post("/auth/sign-up", data);
    console.log(signin);
  } catch (error: any) {
    // console.log(error?.response?.data.mesage);
    console.log(error);
    return { call_error: error?.response?.data.mesage };
  }

  redirect("/verify");
};

export const verify = async (formdata: FormData) => {
  const data = {
    otp: formdata.get("otp"),
  };
  console.log(data);
  try {
    const res = await axiosInstance.post("/auth/otp-verification", data);
    console.log(res);
  } catch (error) {
    console.log(error);
  }
  redirect("/login");
};
export const login = async (prev: any, formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  let user_role;
  try {
    const res = await axiosInstance.post("/auth/login", data);
    console.log(res.data);
    const { access, refresh, role } = res.data;
    // user_role = role;

    cookies().set("access_token", access, {
      maxAge: 60 * 60 * 24,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    cookies().set("refresh_token", refresh, {
      maxAge: 60 * 60 * 24 * 7,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    cookies().set("role", role, {
      maxAge: 60 * 60 * 24 * 7 * 365,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
  } catch (error: any) {
    return { call_errors: error?.response?.data?.detail };
  }

  // redirect("/dashboard");
};

export const forget_password = async (formdata: FormData) => {
  const data = {
    email: formdata.get("email"),
  };
  try {
  } catch (error) {}
};
