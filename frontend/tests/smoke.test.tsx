import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

// Mock the auth queries before the module under test is imported.
// `useLogin` exposes the subset of useMutation we actually use; `useMe`
// returns an idle/empty state so the "already logged in" redirect doesn't run.
vi.mock("@/api/queries/auth", () => {
  return {
    useLogin: () => ({
      mutateAsync: vi.fn(),
      isPending: false,
    }),
    useMe: () => ({ data: null, isLoading: false, isError: false }),
  };
});

import LoginPage from "@/routes/LoginPage";

describe("LoginPage", () => {
  it("renders the email input", () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );
    const email = screen.getByLabelText(/email/i);
    expect(email).toBeInTheDocument();
    expect(email).toHaveAttribute("type", "email");
  });

  it("renders the submit button", () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});
