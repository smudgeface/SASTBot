import cookiePlugin from "@fastify/cookie";
import corsPlugin from "@fastify/cors";
import swaggerPlugin from "@fastify/swagger";
import swaggerUiPlugin from "@fastify/swagger-ui";
import Fastify, { type FastifyInstance } from "fastify";
import {
  type ZodTypeProvider,
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
} from "fastify-type-provider-zod";

import { loadConfig } from "./config.js";
import { prisma, registerPrismaShutdown } from "./db.js";
import authPlugin from "./plugins/auth.js";
import { closeRedis } from "./queue/connection.js";
import { closeScanQueue } from "./queue/scanQueue.js";
import adminCredentialsRoutes from "./routes/adminCredentials.js";
import adminReposRoutes from "./routes/adminRepos.js";
import adminSettingsRoutes from "./routes/adminSettings.js";
import authRoutes from "./routes/auth.js";
import healthRoutes from "./routes/health.js";
import scansRoutes from "./routes/scans.js";
import { ensureCanary } from "./security/crypto.js";
import { bootstrapIfEmpty } from "./services/bootstrap.js";

export async function buildServer(): Promise<FastifyInstance> {
  const config = loadConfig();

  const app = Fastify({
    logger: {
      level: config.logLevel,
      transport:
        process.env.NODE_ENV === "production"
          ? undefined
          : {
              target: "pino-pretty",
              options: { translateTime: "HH:MM:ss.l", singleLine: true },
            },
    },
    trustProxy: true,
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  await app.register(corsPlugin, {
    origin: config.appOrigin,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  });

  await app.register(cookiePlugin, {});

  await app.register(swaggerPlugin, {
    openapi: {
      info: {
        title: "SASTBot API",
        description:
          "LLM-augmented SAST/SCA tool. M1 walking skeleton: auth, repos, settings, credentials, scans (stub).",
        version: "0.1.0",
      },
      servers: [{ url: "/" }],
      components: {
        securitySchemes: {
          cookieAuth: {
            type: "apiKey",
            in: "cookie",
            name: "sastbot_session",
          },
        },
      },
    },
    transform: jsonSchemaTransform,
  });

  await app.register(swaggerUiPlugin, {
    routePrefix: "/docs",
    uiConfig: { docExpansion: "list", deepLinking: true },
  });

  // Expose the raw OpenAPI spec at /openapi.json so the frontend's
  // `npm run gen:types` can hit a stable, well-known URL.
  app.get("/openapi.json", async () => app.swagger());

  await app.register(authPlugin);

  await app.register(healthRoutes);
  await app.register(authRoutes);
  await app.register(adminReposRoutes);
  await app.register(adminSettingsRoutes);
  await app.register(adminCredentialsRoutes);
  await app.register(scansRoutes);

  app.setErrorHandler((err, _req, reply) => {
    // Zod validation errors come through with a `.issues` array; let
    // fastify-type-provider-zod turn them into 400s by default.
    const statusCode = err.statusCode ?? 500;
    if (statusCode >= 500) {
      app.log.error({ err }, "Unhandled error");
    }
    reply.code(statusCode).send({
      detail: err.message || "Internal server error",
    });
  });

  return app;
}

async function start(): Promise<void> {
  const config = loadConfig();
  let app: FastifyInstance | undefined;

  try {
    // Ensure DB connectivity before touching crypto.
    await prisma.$connect();

    // MUST run before anything that might write secrets. Aborts boot if the
    // MASTER_KEY does not match the stored canary.
    await ensureCanary();
    await bootstrapIfEmpty();

    app = await buildServer();
    registerPrismaShutdown();

    await app.listen({ host: "0.0.0.0", port: config.port });
    app.log.info(
      `SASTBot backend listening on :${config.port} — docs at http://localhost:${config.port}/docs`,
    );

    const shutdown = async (signal: string): Promise<void> => {
      app?.log.info({ signal }, "Shutting down");
      try {
        await app?.close();
      } catch {
        // best-effort
      }
      await closeScanQueue().catch(() => undefined);
      await closeRedis().catch(() => undefined);
      await prisma.$disconnect().catch(() => undefined);
      process.exit(0);
    };
    process.on("SIGTERM", () => void shutdown("SIGTERM"));
    process.on("SIGINT", () => void shutdown("SIGINT"));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("[sastbot] fatal startup error:", err);
    try {
      await app?.close();
    } catch {
      // ignore
    }
    await prisma.$disconnect().catch(() => undefined);
    process.exit(1);
  }
}

// Only auto-start when invoked directly (not when imported by tests).
const isEntrypoint = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  // tsx and node both expose the entry via argv[1]; compare by suffix.
  return entry.endsWith("server.ts") || entry.endsWith("server.js");
})();

if (isEntrypoint) {
  void start();
}
