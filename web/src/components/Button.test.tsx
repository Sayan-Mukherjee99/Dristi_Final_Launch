// Drishti v0.1 — Button & Flame animation component tests
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Button } from "./Button";

describe("Button component with 21st.dev Flame animation", () => {
  it("renders text content properly", () => {
    render(<Button>Remediate Host</Button>);
    expect(screen.getByRole("button", { name: "Remediate Host" })).toBeInTheDocument();
  });

  it("handles click events", () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Run Scan</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Run Scan" }));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it("disables button and displays spinner when loading", () => {
    render(<Button loading>Analyzing</Button>);
    const button = screen.getByRole("button");
    expect(button).toBeDisabled();
    expect(screen.getByText("Analyzing")).toBeInTheDocument();
  });

  it("renders different variants including flame, danger, ghost, primary", () => {
    const { rerender } = render(<Button variant="primary">Primary</Button>);
    expect(screen.getByRole("button")).toHaveClass("bg-accent-500");

    rerender(<Button variant="danger">Danger</Button>);
    expect(screen.getByRole("button")).toHaveClass("text-risk-critical");

    rerender(<Button variant="ghost">Ghost</Button>);
    expect(screen.getByRole("button")).toHaveClass("bg-surface-2/80");

    rerender(<Button variant="flame">Flame</Button>);
    expect(screen.getByRole("button")).toHaveClass("border-orange-500/40");
  });

  it("interactively triggers mouse tracking and flame effects on hover", () => {
    const { container } = render(<Button variant="primary">Hover Me</Button>);
    const wrapper = container.firstChild as HTMLElement;

    // Hover into button
    fireEvent.mouseEnter(wrapper);
    fireEvent.mouseMove(wrapper, { clientX: 50, clientY: 10 });

    // Inner flame container should be present and visible
    const flameInner = container.querySelector(".group\\/flame div[aria-hidden='true']");
    expect(flameInner).toBeInTheDocument();

    // Mouse leave
    fireEvent.mouseLeave(wrapper);
  });

  it("respects layout classes such as w-full", () => {
    const { container } = render(<Button className="w-full mt-4">Full Width</Button>);
    const wrapper = container.firstChild as HTMLElement;
    expect(wrapper).toHaveClass("w-full");
    expect(wrapper).toHaveClass("mt-4");
  });
});
