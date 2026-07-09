import { redirect } from "next/navigation";

export default function Home() {
  // Authenticated users land on the queue; the console layout redirects
  // unauthenticated visitors to /login.
  redirect("/alerts");
}
