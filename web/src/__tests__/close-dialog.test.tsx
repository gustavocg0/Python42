import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CloseDialog } from "@/components/alerts/CloseDialog";

describe("CloseDialog", () => {
  it("requires a close reason before submitting (AC-45)", () => {
    const onSubmit = vi.fn();
    render(<CloseDialog count={1} onSubmit={onSubmit} onCancel={() => {}} />);

    const submit = screen.getByRole("button", { name: /close alert/i });
    expect(submit).toBeDisabled();

    fireEvent.click(submit);
    expect(onSubmit).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByLabelText(/false alarm/i, { exact: false }),
    );
    expect(submit).toBeEnabled();

    fireEvent.click(submit);
    expect(onSubmit).toHaveBeenCalledWith("false_positive", undefined);
  });

  it("passes the optional comment through", () => {
    const onSubmit = vi.fn();
    render(<CloseDialog count={3} onSubmit={onSubmit} onCancel={() => {}} />);

    fireEvent.click(screen.getByLabelText(/fixed/i, { exact: false }));
    fireEvent.change(screen.getByLabelText(/comment/i), {
      target: { value: "patched the machine" },
    });
    fireEvent.click(screen.getByRole("button", { name: /close alerts/i }));
    expect(onSubmit).toHaveBeenCalledWith("resolved", "patched the machine");
  });

  it("closes on Escape without submitting", () => {
    const onCancel = vi.fn();
    const onSubmit = vi.fn();
    render(<CloseDialog count={1} onSubmit={onSubmit} onCancel={onCancel} />);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("is announced as a modal dialog", () => {
    render(<CloseDialog count={1} onSubmit={() => {}} onCancel={() => {}} />);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });
});
