import { defineRouteConfig } from "@medusajs/admin-sdk";
import { MagnifyingGlassMini } from "@medusajs/icons";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Container,
  Heading,
  Input,
  Select,
  Skeleton,
  Table,
  Text,
} from "@medusajs/ui";
import { useEffect, useMemo, useState } from "react";
import { Link as RouterLink } from "react-router-dom";

import makePaySidebarIcon from "../../assets/makepay-sidebar-icon.jpg?inline";
import { ErrorNotice } from "../../components/error-notice";
import { ExternalLink } from "../../components/external-link";
import { MakePayStatusBadge } from "../../components/makepay-status-badge";
import { formatDateTime, formatMoney } from "../../lib/format";
import {
  getErrorMessage,
  makePayAdmin,
  makePayQueryKeys,
} from "../../lib/makepay-client";
import type { MakePayPaymentsQuery } from "../../types";

const PAGE_SIZE = 20;

const MakePaySidebarIcon = () => (
  <img
    alt=""
    aria-hidden="true"
    className="block h-full w-full object-cover"
    data-testid="makepay-sidebar-logo"
    draggable={false}
    src={makePaySidebarIcon}
  />
);

const MakePayPaymentsPage = () => {
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [pageIndex, setPageIndex] = useState(0);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setQuery(search.trim());
      setPageIndex(0);
    }, 300);

    return () => window.clearTimeout(timeout);
  }, [search]);

  const paymentsQuery = useMemo<MakePayPaymentsQuery>(
    () => ({
      q: query || undefined,
      status: status === "all" ? undefined : status,
      limit: PAGE_SIZE,
      offset: pageIndex * PAGE_SIZE,
    }),
    [pageIndex, query, status],
  );

  const listQuery = useQuery({
    queryKey: makePayQueryKeys.payments(paymentsQuery),
    queryFn: () => makePayAdmin.listPayments(paymentsQuery),
    placeholderData: keepPreviousData,
  });

  const payments = listQuery.data?.payments ?? [];
  const count = listQuery.data?.count ?? 0;
  const pageCount = Math.max(1, Math.ceil(count / PAGE_SIZE));

  return (
    <Container className="divide-y p-0" data-testid="makepay-payments-page">
      <div className="flex flex-col gap-y-4 px-6 py-4 lg:flex-row lg:items-end lg:justify-between lg:gap-x-6">
        <div>
          <Heading level="h1">MakePay payments</Heading>
          <Text size="small" className="mt-1 text-ui-fg-subtle">
            Payments created by this Medusa installation. Statuses are
            read-only.
          </Text>
        </div>
        <div className="flex w-full flex-col gap-2 sm:flex-row lg:w-auto">
          <div className="relative min-w-0 sm:w-72">
            <MagnifyingGlassMini
              aria-hidden="true"
              className="pointer-events-none absolute left-2.5 top-1/2 z-10 -translate-y-1/2 text-ui-fg-muted"
            />
            <Input
              aria-label="Search MakePay payments"
              className="w-full pl-8"
              placeholder="Search UID, order, or customer"
              size="small"
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <Select
            size="small"
            value={status}
            onValueChange={(value) => {
              setStatus(value);
              setPageIndex(0);
            }}
          >
            <Select.Trigger
              aria-label="Filter by MakePay status"
              className="min-w-40"
            >
              <Select.Value />
            </Select.Trigger>
            <Select.Content>
              <Select.Item value="all">All statuses</Select.Item>
              <Select.Item value="complete">Complete</Select.Item>
              <Select.Item value="pending">Pending</Select.Item>
              <Select.Item value="failed">Failed</Select.Item>
              <Select.Item value="cancelled">Cancelled</Select.Item>
              <Select.Item value="expired">Expired</Select.Item>
            </Select.Content>
          </Select>
        </div>
      </div>

      {listQuery.isError && (
        <div className="px-6 py-5">
          <ErrorNotice message={getErrorMessage(listQuery.error)} />
        </div>
      )}

      {!listQuery.isError && (
        <div className="overflow-x-auto">
          <Table>
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>Payment</Table.HeaderCell>
                <Table.HeaderCell>Order</Table.HeaderCell>
                <Table.HeaderCell>Customer</Table.HeaderCell>
                <Table.HeaderCell className="text-right">
                  Amount
                </Table.HeaderCell>
                <Table.HeaderCell>MakePay</Table.HeaderCell>
                <Table.HeaderCell>Medusa</Table.HeaderCell>
                <Table.HeaderCell>Updated</Table.HeaderCell>
                <Table.HeaderCell className="text-right">
                  Links
                </Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {listQuery.isPending &&
                Array.from({ length: 5 }).map((_, index) => (
                  <Table.Row key={index}>
                    <td colSpan={8} className="h-12 px-6 py-0">
                      <Skeleton className="h-5 w-full" />
                    </td>
                  </Table.Row>
                ))}

              {!listQuery.isPending && payments.length === 0 && (
                <Table.Row>
                  <td colSpan={8} className="h-32 px-6 py-0 text-center">
                    <Text size="small" weight="plus">
                      No MakePay payments found
                    </Text>
                    <Text size="small" className="mt-1 text-ui-fg-subtle">
                      {query || status !== "all"
                        ? "Try changing the search or status filter."
                        : "Payments will appear after customers choose MakePay at checkout."}
                    </Text>
                  </td>
                </Table.Row>
              )}

              {payments.map((payment) => (
                <Table.Row key={payment.id}>
                  <Table.Cell>
                    <Text size="small" weight="plus" family="mono">
                      {payment.payment_link_uid}
                    </Text>
                    {payment.session_id && (
                      <Text
                        size="xsmall"
                        className="mt-0.5 text-ui-fg-subtle"
                        family="mono"
                      >
                        {payment.session_id}
                      </Text>
                    )}
                  </Table.Cell>
                  <Table.Cell>
                    {payment.order_id ? (
                      <RouterLink
                        className="text-ui-fg-interactive hover:text-ui-fg-interactive-hover txt-compact-small-plus"
                        to={`/orders/${encodeURIComponent(payment.order_id)}`}
                      >
                        {payment.order_display_id || payment.order_id}
                      </RouterLink>
                    ) : (
                      <Text size="small" className="text-ui-fg-subtle">
                        Pending order
                      </Text>
                    )}
                  </Table.Cell>
                  <Table.Cell>
                    <Text size="small">{payment.customer_email || "—"}</Text>
                  </Table.Cell>
                  <Table.Cell className="text-right">
                    <Text size="small" weight="plus">
                      {formatMoney(payment.amount, payment.currency)}
                    </Text>
                  </Table.Cell>
                  <Table.Cell>
                    <MakePayStatusBadge status={payment.provider_status} />
                  </Table.Cell>
                  <Table.Cell>
                    <MakePayStatusBadge status={payment.medusa_status} />
                  </Table.Cell>
                  <Table.Cell>
                    <Text size="small">
                      {formatDateTime(
                        payment.last_synced_at || payment.updated_at,
                      )}
                    </Text>
                  </Table.Cell>
                  <Table.Cell>
                    <div className="flex justify-end gap-x-3 whitespace-nowrap">
                      <ExternalLink
                        href={payment.public_url}
                        label={`Open hosted checkout for ${payment.payment_link_uid}`}
                      >
                        Checkout
                      </ExternalLink>
                      <ExternalLink
                        href={payment.dashboard_url}
                        label={`Open ${payment.payment_link_uid} in MakePay`}
                      >
                        MakePay
                      </ExternalLink>
                    </div>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      )}

      {!listQuery.isError && (
        <Table.Pagination
          count={count}
          pageSize={PAGE_SIZE}
          pageIndex={pageIndex}
          pageCount={pageCount}
          canPreviousPage={pageIndex > 0}
          canNextPage={(pageIndex + 1) * PAGE_SIZE < count}
          previousPage={() =>
            setPageIndex((current) => Math.max(0, current - 1))
          }
          nextPage={() =>
            setPageIndex((current) => Math.min(pageCount - 1, current + 1))
          }
        />
      )}
    </Container>
  );
};

export const config = defineRouteConfig({
  label: "MakePay",
  icon: MakePaySidebarIcon,
});

export default MakePayPaymentsPage;
