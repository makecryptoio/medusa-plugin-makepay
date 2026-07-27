import { defineWidgetConfig } from "@medusajs/admin-sdk";
import type { AdminOrder, DetailWidgetProps } from "@medusajs/framework/types";
import { ArrowPath, CreditCard } from "@medusajs/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Container,
  Heading,
  Skeleton,
  Text,
  toast,
} from "@medusajs/ui";

import { ErrorNotice } from "../components/error-notice";
import { ExternalLink } from "../components/external-link";
import { MakePayStatusBadge } from "../components/makepay-status-badge";
import { formatDateTime, formatMoney } from "../lib/format";
import {
  getErrorMessage,
  makePayAdmin,
  makePayQueryKeys,
} from "../lib/makepay-client";

const OrderMakePayWidget = ({ data: order }: DetailWidgetProps<AdminOrder>) => {
  const queryClient = useQueryClient();
  const orderPaymentQuery = useQuery({
    queryKey: makePayQueryKeys.order(order.id),
    queryFn: () => makePayAdmin.getOrderPayment(order.id),
  });
  const connectionQuery = useQuery({
    queryKey: makePayQueryKeys.connection(),
    queryFn: makePayAdmin.getConnection,
  });

  const payment = orderPaymentQuery.data?.payment;
  const canReconcile =
    connectionQuery.data?.capabilities.reconcile === true &&
    payment?.auth_mode === connectionQuery.data.connection.auth_mode;
  const reconcileMutation = useMutation({
    mutationFn: makePayAdmin.reconcilePayment,
    onSuccess: async (response) => {
      queryClient.setQueryData(makePayQueryKeys.order(order.id), response);
      if (response.payment) {
        queryClient.setQueryData(
          makePayQueryKeys.payment(response.payment.id),
          response,
        );
      }
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ["makepay", "payments"],
        }),
        queryClient.invalidateQueries({
          queryKey: ["orders", "detail", order.id],
        }),
      ]);
      toast.success("MakePay payment reconciled");
    },
    onError: (error) => {
      toast.error("Couldn't reconcile payment", {
        description: getErrorMessage(error),
      });
    },
  });

  if (orderPaymentQuery.isPending) {
    return (
      <Container className="flex flex-col gap-y-3 px-6 py-4">
        <Skeleton className="h-5 w-36" />
        <Skeleton className="h-5 w-full" />
        <Skeleton className="h-5 w-3/4" />
      </Container>
    );
  }

  if (!payment && !orderPaymentQuery.isError) {
    return <></>;
  }

  return (
    <Container className="divide-y p-0" data-testid="makepay-order-widget">
      <div className="flex items-center justify-between gap-x-3 px-6 py-4">
        <div className="flex items-center gap-x-2">
          <CreditCard aria-hidden="true" className="text-ui-fg-muted" />
          <Heading level="h2">MakePay</Heading>
        </div>
        {payment && canReconcile && (
          <Button
            variant="secondary"
            size="small"
            isLoading={reconcileMutation.isPending}
            onClick={() => reconcileMutation.mutate(payment.id)}
          >
            <ArrowPath aria-hidden="true" />
            Reconcile
          </Button>
        )}
      </div>

      {orderPaymentQuery.isError && (
        <div className="px-6 py-4">
          <ErrorNotice message={getErrorMessage(orderPaymentQuery.error)} />
        </div>
      )}

      {payment && (
        <div className="flex flex-col gap-y-3 px-6 py-4">
          {!canReconcile && (
            <Text size="small" className="text-ui-fg-subtle">
              Reconciliation is unavailable for this payment's authentication
              mode or requires distributed locking.
            </Text>
          )}
          <div className="flex items-center justify-between gap-x-3">
            <Text size="small" className="text-ui-fg-subtle">
              Amount
            </Text>
            <Text size="small" weight="plus">
              {formatMoney(payment.amount, payment.currency)}
            </Text>
          </div>
          <div className="flex items-center justify-between gap-x-3">
            <Text size="small" className="text-ui-fg-subtle">
              MakePay status
            </Text>
            <MakePayStatusBadge status={payment.provider_status} />
          </div>
          <div className="flex items-center justify-between gap-x-3">
            <Text size="small" className="text-ui-fg-subtle">
              Medusa status
            </Text>
            <MakePayStatusBadge status={payment.medusa_status} />
          </div>
          <div className="flex items-start justify-between gap-x-3">
            <Text size="small" className="text-ui-fg-subtle">
              Payment UID
            </Text>
            <Text size="small" family="mono" className="break-all text-right">
              {payment.payment_link_uid}
            </Text>
          </div>
          {payment.company_id && (
            <div className="flex items-start justify-between gap-x-3">
              <Text size="small" className="text-ui-fg-subtle">
                Company
              </Text>
              <Text size="small" family="mono" className="break-all text-right">
                {payment.company_id}
              </Text>
            </div>
          )}
          <div className="flex items-center justify-between gap-x-3">
            <Text size="small" className="text-ui-fg-subtle">
              Last synchronized
            </Text>
            <Text size="small">
              {formatDateTime(payment.last_synced_at || payment.updated_at)}
            </Text>
          </div>
          <div className="flex flex-wrap justify-end gap-x-4 gap-y-2 pt-1">
            <ExternalLink
              href={payment.public_url}
              label={`Open hosted checkout for ${payment.payment_link_uid}`}
            >
              Hosted checkout
            </ExternalLink>
            <ExternalLink
              href={payment.dashboard_url}
              label={`Open ${payment.payment_link_uid} in MakePay`}
            >
              Open in MakePay
            </ExternalLink>
          </div>
          <Text size="xsmall" className="text-ui-fg-subtle">
            Automated refunds aren&apos;t supported. Verify any off-platform
            refund has settled before recording its accounting adjustment in
            Medusa.
          </Text>
        </div>
      )}
    </Container>
  );
};

export const config = defineWidgetConfig({
  zone: "order.details.side.after",
  id: "makepay:order-payment",
});

export default OrderMakePayWidget;
