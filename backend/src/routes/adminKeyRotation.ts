/**
 * Admin MASTER_KEY rotation route.
 *
 * POST /admin/db/rotate-master-key
 *   Re-encrypts the encryption canary + every credential from the instance's
 *   CURRENT MASTER_KEY to a fresh operator-supplied key, in one transaction.
 *   Replaces the old manual "delete the canary row + re-enter every credential"
 *   dance (see docs/user-manual/admin-deployment.md).
 *
 * IMPORTANT — this endpoint does NOT restart the backend.
 *   After a successful rewrap the at-rest data is encrypted under the NEW key,
 *   but this running process still holds the OLD key in its environment. It can
 *   no longer decrypt credentials, and a restart under the old `MASTER_KEY`
 *   would FAIL the canary and refuse to boot. The operator MUST update the
 *   `MASTER_KEY` environment variable to the new value and restart promptly.
 *   The response spells this out; the UI shows it prominently.
 *
 * The unavoidable window: between the rewrap committing and the operator
 * updating the env + restarting, an unexpected restart will brick boot. This is
 * inherent to in-place key rotation (the boot canary only knows one key) and is
 * the same constraint the manual dance had. Take a backup first.
 */

import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { ErrorSchema } from "../schemas.js";
import { loadMasterKey, masterKeyFingerprint } from "../security/crypto.js";
import { KeyRewrapError, rewrapAllSecrets } from "../services/keyRewrap.js";

const RotateRequestSchema = z.object({
  /** Base64-encoded 32-byte target key — the same shape as MASTER_KEY. */
  new_master_key: z.string().min(1),
  /** Type-to-confirm guard; the UI sends the literal string. */
  confirm: z.literal("ROTATE"),
});

const RotateResponseSchema = z.object({
  ok: z.boolean(),
  rewrapped_credentials: z.number().int(),
  /** Fingerprint of the NEW key — so the operator can confirm what to set. */
  new_key_fingerprint: z.string(),
  /** Operator next-steps (set MASTER_KEY + restart). */
  next_steps: z.string(),
});

const adminKeyRotationRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.post(
    "/admin/db/rotate-master-key",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "backup"],
        summary: "Rotate the MASTER_KEY: re-encrypt the canary and all credentials to a new key",
        description:
          "Re-encrypts the encryption canary and every stored credential from this " +
          "instance's current MASTER_KEY to a new operator-supplied key, atomically. " +
          "Does NOT restart the backend — after a successful rotation you MUST set the " +
          "MASTER_KEY environment variable to the new value and restart, or the next " +
          "boot will fail the encryption canary. Take a backup first.",
        body: RotateRequestSchema,
        response: {
          200: RotateResponseSchema,
          400: ErrorSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          500: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      // Decode + validate the target key (32 bytes, like MASTER_KEY).
      const newKey = Buffer.from(req.body.new_master_key.trim(), "base64");
      if (newKey.length !== 32) {
        newKey.fill(0);
        return reply.code(400).send({
          detail:
            "new_master_key must be base64 that decodes to exactly 32 bytes " +
            "(generate one with: openssl rand -base64 32).",
        });
      }

      // The current key comes from this instance's own environment — never
      // supplied by the client, so there's no wrong-current-key failure mode.
      const currentKey = loadMasterKey();
      if (newKey.equals(currentKey)) {
        newKey.fill(0);
        return reply.code(400).send({
          detail: "The new key is identical to the current MASTER_KEY — nothing to rotate.",
        });
      }

      const newKeyFingerprint = masterKeyFingerprint(newKey);

      try {
        const counts = await rewrapAllSecrets(currentKey, newKey);
        app.log.info(
          { credentials: counts.credentials, newKeyFingerprint },
          "MASTER_KEY rotation: re-keyed canary + credentials to the new key — operator must update env + restart",
        );
        return reply.code(200).send({
          ok: true,
          rewrapped_credentials: counts.credentials,
          new_key_fingerprint: newKeyFingerprint,
          next_steps:
            "The database is now encrypted with the NEW key. Update the MASTER_KEY " +
            "environment variable to the new value and restart the backend (and worker) " +
            "NOW. Until you do, this instance cannot decrypt credentials, and a restart " +
            "under the old key will fail the encryption canary.",
        });
      } catch (err) {
        const isRewrapErr = err instanceof KeyRewrapError;
        app.log.error(
          { err: (err as Error).message },
          "MASTER_KEY rotation failed — data is unchanged (still encrypted under the current key)",
        );
        return reply.code(500).send({
          detail:
            `MASTER_KEY rotation failed${isRewrapErr ? ` (${(err as Error).message})` : ""}. ` +
            `No data was changed — the database is still encrypted with the current key, ` +
            `and this instance continues to operate normally. No restart is needed.`,
        });
      } finally {
        // Scrub our copy of the new key. The operator already holds it client-side.
        newKey.fill(0);
      }
    },
  );
};

export default adminKeyRotationRoutes;
