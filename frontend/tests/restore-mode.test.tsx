/**
 * Tests for the restore mode radio selector in the Settings page DB restore section.
 *
 * Verifies:
 * - Default selection is "full".
 * - Toggling to "runtime" changes the fetch URL to include ?mode=runtime.
 * - Toggling back to "full" changes the fetch URL to include ?mode=full.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";

// ---- Module mocks (must appear before the import under test) ----

vi.mock("@/api/queries/settings", () => ({
  useSettings: () => ({ data: null, isLoading: false }),
  useUpdateSettings: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useCheckLlm: () => ({ mutate: vi.fn(), isPending: false, data: null }),
}));

vi.mock("@/api/queries/credentials", () => ({
  useCredentials: () => ({ data: { items: [] }, isLoading: false }),
}));

vi.mock("@/api/queries/jira", () => ({
  useCheckJiraConnection: () => ({ mutate: vi.fn(), isPending: false, data: null }),
}));

vi.mock("@/api/queries/version", () => ({
  useVersion: () => ({ data: null }),
}));

vi.mock("@/components/ui/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import SettingsPage from "@/routes/admin/SettingsPage";

// ---- helpers ----

function setup() {
  const user = userEvent.setup();
  render(
    <MemoryRouter>
      <SettingsPage />
    </MemoryRouter>,
  );
  return { user };
}

describe("RestoreSection — mode radio", () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    vi.stubGlobal("fetch", vi.fn());
  });

  it("defaults to full restore mode", () => {
    setup();
    const fullRadio = screen.getByTestId("restore-mode-full") as HTMLInputElement;
    const runtimeRadio = screen.getByTestId("restore-mode-runtime") as HTMLInputElement;
    expect(fullRadio.checked).toBe(true);
    expect(runtimeRadio.checked).toBe(false);
  });

  it("shows the caution banner only when runtime mode is selected", async () => {
    const { user } = setup();

    // No caution visible initially
    expect(
      screen.queryByText(/deleted any repos or upgraded the backend/i),
    ).toBeNull();

    // Select runtime
    await user.click(screen.getByTestId("restore-mode-runtime"));

    expect(
      screen.getByText(/deleted any repos or upgraded the backend/i),
    ).toBeInTheDocument();

    // Switch back to full — caution disappears
    await user.click(screen.getByTestId("restore-mode-full"));

    expect(
      screen.queryByText(/deleted any repos or upgraded the backend/i),
    ).toBeNull();
  });

  it("uses ?mode=full in the request URL when full mode is selected", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, restarting: true, migrations_applied: [] }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const { user } = setup();

    // Upload a file
    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]')!;
    const file = new File(["dummy"], "backup.tar.gz", { type: "application/gzip" });
    await user.upload(fileInput, file);

    // Click "Restore…" to open the dialog
    await user.click(screen.getByRole("button", { name: /restore…/i }));

    // Type the confirmation word
    const confirmInput = await screen.findByPlaceholderText("RESTORE");
    await user.type(confirmInput, "RESTORE");

    // Click "Restore database"
    await user.click(screen.getByRole("button", { name: /restore database/i }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining("?mode=full"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("uses ?mode=runtime in the request URL when runtime mode is selected", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, restarting: true, migrations_applied: [] }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const { user } = setup();

    // Switch to runtime mode
    await user.click(screen.getByTestId("restore-mode-runtime"));

    // Upload a file
    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]')!;
    const file = new File(["dummy"], "backup.tar.gz", { type: "application/gzip" });
    await user.upload(fileInput, file);

    // Click "Restore…"
    await user.click(screen.getByRole("button", { name: /restore…/i }));

    // Confirm
    const confirmInput = await screen.findByPlaceholderText("RESTORE");
    await user.type(confirmInput, "RESTORE");

    await user.click(screen.getByRole("button", { name: /restore database/i }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining("?mode=runtime"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });
});
