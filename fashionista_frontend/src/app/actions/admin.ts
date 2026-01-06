"use server";

import { z } from "zod";
import { fetchWithAuth } from "../utils/fetchAuth";
const schema = z.object({});

export const getAllColloections = async () => {
  try {
    const res = await fetchWithAuth("/collections/");
    console.log(res);
  } catch (error) {
    console.log(error);
  }
};
export const newCollection = async (formdata: FormData) => {
  const data = Object.fromEntries(formdata.entries());
  const validated = schema.safeParse(data);
  if (!validated.success) {
    return {
      errors: validated.error.flatten().fieldErrors,
    };
  }
  try {
    const res = await fetchWithAuth("/collections/", "post", formdata);
    console.log(res);
  } catch (error) {
    console.log(error);
  }
};
