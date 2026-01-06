import { checkUserRole } from "../utils/lib";

export default async function Layout({
  client,
  vendor,
}: {
  client: React.ReactNode;
  vendor: React.ReactNode;
}) {
  const role = await checkUserRole();
  // console.log(role);

  return <>{role == "Vendor" ? vendor : client}</>;
}
