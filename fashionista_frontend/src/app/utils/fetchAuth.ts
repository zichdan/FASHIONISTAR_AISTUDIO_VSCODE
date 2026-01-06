import { cookies } from "next/headers";
import { axiosInstance } from "./axiosInstance";

export const fetchWithAuth = async (
  url: string,
  method: "get" | "post" | "put" | "delete" | "patch" = "get",
  data: null | object | FormData = null,
  content = "application/json"
) => {
  const accessToken = cookies().get("access_token")?.value;
  const refreshToken = cookies().get("refresh_token")?.value;
  console.log(accessToken);
  try {
    const response = await axiosInstance({
      url,
      method,
      withCredentials: true,
      headers: {
        "Content-type": content,
        Authorization: `Bearer ${accessToken}`,
      },
      data,
    });
    return response.data;
  } catch (error: any) {
    if (error.response && error.response.status === 401) {
      try {
        const refreshResponse = await axiosInstance.post("/auth/refresh", {
          refresh: refreshToken,
        });

        const newAccessToken = refreshResponse.data.access;

        // const resp = await fetch(`${process.env.URL}/api/setcookie`, {
        //   method: "POST",
        //   body: JSON.stringify({
        //     accessToken: newAccessToken,
        //   }),
        // });
        // console.log("cookie response", resp);
        try {
          const retryResponse = await axiosInstance({
            method,
            url,
            headers: {
              Authorization: `Bearer ${newAccessToken}`,
            },
            data,
          });
          return retryResponse.data;
        } catch (error) {
          console.log("retry response error", error);
        }
      } catch (refreshError) {
        console.error("Error refreshing access token:", refreshError);
        throw refreshError;
      }
    }
    // console.log(error);

    throw error; // Re-throw other errors
  }
};
