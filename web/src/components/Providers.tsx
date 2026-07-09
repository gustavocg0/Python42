"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { setApiHandlers } from "@/lib/api/client";
import { isApiError } from "@/lib/api/errors";
import { ToastProvider } from "./Toast";
import { TenantStateProvider, useTenantState } from "./TenantState";

const PUBLIC_ROUTES = ["/login", "/signup"];

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/** Binds central API error handling: 401 -> login, 403 TENANT_FROZEN -> banner. */
function ApiHandlerBinder({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { reportFrozen } = useTenantState();

  useEffect(() => {
    setApiHandlers({
      onUnauthorized: () => {
        if (!isPublicRoute(pathname)) {
          router.replace(`/login?next=${encodeURIComponent(pathname)}`);
        }
      },
      onTenantFrozen: (cause) => reportFrozen(cause),
    });
    return () => setApiHandlers({});
  }, [router, pathname, reportFrozen]);

  return <>{children}</>;
}

export default function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 15_000,
            refetchOnWindowFocus: false,
            retry: (failureCount, error) => {
              // Never retry client errors (4xx); retry transient ones twice.
              if (isApiError(error) && error.status < 500) return false;
              return failureCount < 2;
            },
          },
          mutations: { retry: false },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <TenantStateProvider>
        <ToastProvider>
          <ApiHandlerBinder>{children}</ApiHandlerBinder>
        </ToastProvider>
      </TenantStateProvider>
    </QueryClientProvider>
  );
}
