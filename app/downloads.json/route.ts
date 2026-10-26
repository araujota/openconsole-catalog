import { runtimeCatalog } from "@/lib/runtimes";

export const dynamic = "force-static";

export function GET() {
  return Response.json(runtimeCatalog);
}
