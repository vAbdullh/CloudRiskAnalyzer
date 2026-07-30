import "dotenv/config";
import { defineConfig } from "prisma/config";

const dbUser = encodeURIComponent(process.env.POSTGRES_USER || "");
const dbPassword = encodeURIComponent(process.env.POSTGRES_PASSWORD || "");
const dbHost = process.env.POSTGRES_HOST || "";
const dbPort = process.env.POSTGRES_PORT || "";
const dbName = process.env.POSTGRES_DB || "";

export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: {
    url: `postgresql://${dbUser}:${dbPassword}@${dbHost}:${dbPort}/${dbName}?schema=public`,
  },
});
