import { DOC_VERSION, RUNTIME_TAG, SITE_URL } from "@/lib/docs";
export function GET() { return Response.json({ schema: "openconsole.docs.versions.v1", current: DOC_VERSION, versions: [{ version: DOC_VERSION, runtimeTag: RUNTIME_TAG, status: "development-preview", canonical: `${SITE_URL}/docs/${DOC_VERSION}/overview` }] }); }
