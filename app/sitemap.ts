import type { MetadataRoute } from "next";
import { DOC_VERSION, SITE_URL, docs } from "@/lib/docs";
export default function sitemap(): MetadataRoute.Sitemap { return ["", "/docs", "/docs/versions", ...docs.map((page) => `/docs/${DOC_VERSION}/${page.slug}`)].map((path) => ({ url: `${SITE_URL}${path}`, changeFrequency: path.startsWith("/docs/v") ? "monthly" : "weekly", priority: path === "" ? 1 : .8 })); }
