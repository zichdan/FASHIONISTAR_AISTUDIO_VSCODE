import { cookies } from "next/headers";

export const checkUserRole = async () => {
  const role = cookies().get("role")?.value;
  return role;
};
