// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, act } from "@testing-library/react";
import { Router, Link, useLocation } from "wouter";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

afterEach(cleanup);

const NAV = [
  { path: "/", label: "Dashboard" },
  { path: "/programs", label: "Programs" },
  { path: "/maps", label: "Maps" },
];

/** Mirrors the collapsed sidebar: Tooltip asChild wrapping a wouter Link,
 *  with an active-state class that flips on navigation. */
function CollapsedNav() {
  const [location, navigate] = useLocation();
  return (
    <div>
      <button data-testid="go-programs" onClick={() => navigate("/programs")}>go</button>
      <button data-testid="go-maps" onClick={() => navigate("/maps")}>go maps</button>
      {NAV.map(({ path, label }) => {
        const isActive = location === path;
        return (
          <Tooltip key={path}>
            <TooltipTrigger asChild>
              <Link href={path}>
                <div className={isActive ? "active" : "inactive"}>{label}</div>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">{label}</TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
}

describe("collapsed nav tooltips under navigation", () => {
  it("does not loop when navigating between tabs", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    window.history.replaceState(null, "", "/");
    const r = render(
      <Router>
        <TooltipProvider>
          <CollapsedNav />
        </TooltipProvider>
      </Router>
    );
    act(() => r.getByTestId("go-programs").click());
    act(() => r.getByTestId("go-maps").click());
    act(() => r.getByTestId("go-programs").click());
    const looped = errSpy.mock.calls.some(args =>
      args.some(a => typeof a === "string" && a.includes("Maximum update depth"))
    );
    errSpy.mockRestore();
    expect(looped, "collapsed nav update loop on navigation").toBe(false);
  });
});
