/**
 * Tests for components/fleet-search.tsx — pure-helper matchesBuoy +
 * render behavior of the search/filter row.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

import FleetSearch, { matchesBuoy } from "@/components/fleet-search";


afterEach(cleanup);


describe("matchesBuoy", () => {
  const b = { slug: "alpha", hostname: "buoy-alpha-corp", city: "Kansas City" };

  it("returns true for empty query (no filter)", () => {
    expect(matchesBuoy(b, "")).toBe(true);
    expect(matchesBuoy(b, "   ")).toBe(true);
  });

  it("matches on slug (case-insensitive substring)", () => {
    expect(matchesBuoy(b, "alph")).toBe(true);
    expect(matchesBuoy(b, "ALPHA")).toBe(true);
  });

  it("matches on hostname", () => {
    expect(matchesBuoy(b, "buoy-alpha")).toBe(true);
    expect(matchesBuoy(b, "corp")).toBe(true);
  });

  it("matches on city", () => {
    expect(matchesBuoy(b, "kansas")).toBe(true);
    expect(matchesBuoy(b, "city")).toBe(true);
  });

  it("returns false when nothing matches", () => {
    expect(matchesBuoy(b, "nonexistent")).toBe(false);
  });

  it("handles missing city without crashing", () => {
    const noCity = { slug: "alpha", hostname: "buoy-alpha-corp" };
    expect(matchesBuoy(noCity, "alpha")).toBe(true);
    expect(matchesBuoy(noCity, "kansas")).toBe(false);
  });
});


describe("FleetSearch render", () => {
  it("renders the search input + all four tier chips", () => {
    render(
      <FleetSearch
        value="" onChange={vi.fn()}
        healthFilter={null} onHealthFilter={vi.fn()}
        resultCount={3} totalCount={3}
      />,
    );
    expect(screen.getByPlaceholderText(/search slug/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "DOWN" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "STALE" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "DEGRADED" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "OK" })).toBeTruthy();
  });

  it("calls onChange when the search input changes", () => {
    const onChange = vi.fn();
    render(
      <FleetSearch
        value="" onChange={onChange}
        healthFilter={null} onHealthFilter={vi.fn()}
        resultCount={3} totalCount={3}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText(/search slug/i), {
      target: { value: "alpha" },
    });
    expect(onChange).toHaveBeenCalledWith("alpha");
  });

  it("toggles the health filter on chip click (off → on)", () => {
    const onHealthFilter = vi.fn();
    render(
      <FleetSearch
        value="" onChange={vi.fn()}
        healthFilter={null} onHealthFilter={onHealthFilter}
        resultCount={3} totalCount={3}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "DOWN" }));
    expect(onHealthFilter).toHaveBeenCalledWith("red");
  });

  it("toggles the health filter on chip click (on → off)", () => {
    const onHealthFilter = vi.fn();
    render(
      <FleetSearch
        value="" onChange={vi.fn()}
        healthFilter="red" onHealthFilter={onHealthFilter}
        resultCount={1} totalCount={3}
      />,
    );
    // Already active — clicking should clear.
    fireEvent.click(screen.getByRole("button", { name: "DOWN" }));
    expect(onHealthFilter).toHaveBeenCalledWith(null);
  });

  it("shows 'N of M match' when filtering", () => {
    render(
      <FleetSearch
        value="alpha" onChange={vi.fn()}
        healthFilter={null} onHealthFilter={vi.fn()}
        resultCount={1} totalCount={3}
      />,
    );
    expect(screen.getByText(/1 of 3 match/i)).toBeTruthy();
  });

  it("hides the result counter when nothing is filtered", () => {
    render(
      <FleetSearch
        value="" onChange={vi.fn()}
        healthFilter={null} onHealthFilter={vi.fn()}
        resultCount={3} totalCount={3}
      />,
    );
    expect(screen.queryByText(/match/i)).toBeNull();
  });

  it("'clear ✕' resets both inputs", () => {
    const onChange = vi.fn();
    const onHealthFilter = vi.fn();
    render(
      <FleetSearch
        value="alpha" onChange={onChange}
        healthFilter="yellow" onHealthFilter={onHealthFilter}
        resultCount={1} totalCount={5}
      />,
    );
    fireEvent.click(screen.getByTitle(/clear search/i));
    expect(onChange).toHaveBeenCalledWith("");
    expect(onHealthFilter).toHaveBeenCalledWith(null);
  });

  it("hides the clear button when nothing is filtered", () => {
    render(
      <FleetSearch
        value="" onChange={vi.fn()}
        healthFilter={null} onHealthFilter={vi.fn()}
        resultCount={3} totalCount={3}
      />,
    );
    expect(screen.queryByTitle(/clear search/i)).toBeNull();
  });
});
