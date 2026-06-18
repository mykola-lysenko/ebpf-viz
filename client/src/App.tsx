import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { lazy, Suspense } from "react";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import EbpfLayout from "./components/EbpfLayout";
import Dashboard from "./pages/Dashboard";
import KernelView from "./pages/KernelView";
import NetworkView from "./pages/NetworkView";
import CgroupView from "./pages/CgroupView";
import ProgramsView from "./pages/ProgramsView";
import SettingsView from "./pages/SettingsView";

const OsMapView = lazy(() => import("./pages/OsMapView"));
const MapsView = lazy(() => import("./pages/MapsView"));

function RouteLoading() {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="rounded-xl border border-border bg-card/60 px-4 py-3 text-sm text-muted-foreground shadow-lg">
        Loading view...
      </div>
    </div>
  );
}

function Router() {
  return (
    <EbpfLayout>
      <Suspense fallback={<RouteLoading />}>
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/kernel" component={KernelView} />
          <Route path="/network" component={NetworkView} />
          <Route path="/cgroups" component={CgroupView} />
          <Route path="/programs" component={ProgramsView} />
          <Route path="/settings" component={SettingsView} />
          <Route path="/map" component={OsMapView} />
          <Route path="/maps" component={MapsView} />
          <Route path="/404" component={NotFound} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    </EbpfLayout>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster theme="dark" />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
