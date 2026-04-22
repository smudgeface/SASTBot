-- Rename `credentials.label` to `credentials.name` to match the Repos page
-- convention (name-first column) and read more naturally in both the UI
-- and API.
--
-- Done as a proper RENAME COLUMN so existing credentials keep their human-
-- readable identifier; the default Prisma `migrate dev` on a field rename
-- generates a DROP + ADD which would lose the data.

ALTER TABLE "credentials" RENAME COLUMN "label" TO "name";
