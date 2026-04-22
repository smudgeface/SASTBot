import type { Prisma, Repo } from "@prisma/client";

import { prisma } from "../db.js";
import type { RepoCreate, RepoUpdate } from "../schemas.js";

import { createCredential } from "./credentialService.js";

export class RepoNotFoundError extends Error {
  constructor() {
    super("Repo not found");
    this.name = "RepoNotFoundError";
  }
}

export class RepoConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RepoConflictError";
  }
}

export async function listRepos(orgId: string | null): Promise<Repo[]> {
  return prisma.repo.findMany({
    where: { orgId: orgId ?? null },
    orderBy: { createdAt: "desc" },
  });
}

export async function getRepo(id: string, orgId: string | null): Promise<Repo> {
  const repo = await prisma.repo.findFirst({ where: { id, orgId: orgId ?? null } });
  if (!repo) throw new RepoNotFoundError();
  return repo;
}

export async function createRepo(
  input: RepoCreate,
  orgId: string | null,
  createdBy: string | null,
): Promise<Repo> {
  try {
    return await prisma.$transaction(async (tx) => {
      let credentialId: string | null = input.credential_id ?? null;
      if (input.credential) {
        const cred = await createCredential(
          { orgId, input: input.credential, createdBy },
          tx,
        );
        credentialId = cred.id;
      }

      return tx.repo.create({
        data: {
          orgId: orgId ?? null,
          name: input.name,
          url: input.url,
          protocol: input.protocol,
          credentialId,
          defaultBranch: input.default_branch ?? "main",
          scanPaths: (input.scan_paths ?? ["/"]) as Prisma.InputJsonValue,
          analysisTypes: (input.analysis_types ?? ["sca"]) as Prisma.InputJsonValue,
          scheduleCron: input.schedule_cron ?? null,
          isActive: input.is_active ?? true,
          retainClone: input.retain_clone ?? false,
        },
      });
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new RepoConflictError("A repo with this URL already exists for this org");
    }
    throw err;
  }
}

export async function updateRepo(
  id: string,
  input: RepoUpdate,
  orgId: string | null,
  createdBy: string | null,
): Promise<Repo> {
  const existing = await prisma.repo.findFirst({ where: { id, orgId: orgId ?? null } });
  if (!existing) throw new RepoNotFoundError();

  try {
    return await prisma.$transaction(async (tx) => {
      let credentialId: string | null | undefined;
      if (input.credential) {
        const cred = await createCredential(
          { orgId, input: input.credential, createdBy },
          tx,
        );
        credentialId = cred.id;
      } else if (Object.prototype.hasOwnProperty.call(input, "credential_id")) {
        credentialId = input.credential_id ?? null;
      }

      const data: Prisma.RepoUpdateInput = {};
      if (input.name !== undefined) data.name = input.name;
      if (input.url !== undefined) data.url = input.url;
      if (input.protocol !== undefined) data.protocol = input.protocol;
      if (credentialId !== undefined) {
        data.credential = credentialId
          ? { connect: { id: credentialId } }
          : { disconnect: true };
      }
      if (input.default_branch !== undefined) data.defaultBranch = input.default_branch;
      if (input.scan_paths !== undefined) {
        data.scanPaths = input.scan_paths as Prisma.InputJsonValue;
      }
      if (input.analysis_types !== undefined) {
        data.analysisTypes = input.analysis_types as Prisma.InputJsonValue;
      }
      if (Object.prototype.hasOwnProperty.call(input, "schedule_cron")) {
        data.scheduleCron = input.schedule_cron ?? null;
      }
      if (input.is_active !== undefined) data.isActive = input.is_active;
      if (input.retain_clone !== undefined) data.retainClone = input.retain_clone;

      return tx.repo.update({ where: { id }, data });
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new RepoConflictError("A repo with this URL already exists for this org");
    }
    throw err;
  }
}

export async function deleteRepo(id: string, orgId: string | null): Promise<void> {
  const existing = await prisma.repo.findFirst({ where: { id, orgId: orgId ?? null } });
  if (!existing) throw new RepoNotFoundError();
  await prisma.repo.delete({ where: { id } });
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code: unknown }).code === "P2002"
  );
}
