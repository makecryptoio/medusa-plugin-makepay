import { defineRouteConfig } from "@medusajs/admin-sdk";
import { CogSixTooth, Key, Link } from "@medusajs/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Badge,
  Button,
  Container,
  Heading,
  Skeleton,
  StatusBadge,
  Text,
  toast,
} from "@medusajs/ui";
import { useEffect, useRef, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";

import { ErrorNotice } from "../../../components/error-notice";
import { ExternalLink } from "../../../components/external-link";
import {
  connectionStatusColor,
  formatDateTime,
  humanizeStatus,
  oauthConnectionActionLabel,
  redactSensitiveText,
  safeOAuthRedirect,
  webhookStatusColor,
} from "../../../lib/format";
import {
  getErrorMessage,
  makePayAdmin,
  makePayQueryKeys,
} from "../../../lib/makepay-client";
import type { MakePayConnection } from "../../../types";

const DetailRow = ({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) => (
  <div className="grid grid-cols-1 gap-y-1 px-6 py-3 sm:grid-cols-[180px_1fr] sm:gap-x-4">
    <Text size="small" className="text-ui-fg-subtle">
      {label}
    </Text>
    <div className="min-w-0">{children}</div>
  </div>
);

const ConnectionDetails = ({
  connection,
}: {
  connection: MakePayConnection;
}) => (
  <div className="divide-y">
    <DetailRow label="Connection">
      <StatusBadge color={connectionStatusColor(connection.status)}>
        {humanizeStatus(connection.status)}
      </StatusBadge>
    </DetailRow>
    <DetailRow label="Authentication">
      <div className="flex items-center gap-x-2">
        <Key aria-hidden="true" className="text-ui-fg-muted" />
        <Text size="small">
          {connection.auth_mode === "oauth" ? "MakeCrypto OAuth" : "API key"}
        </Text>
      </div>
      {connection.auth_mode === "api_key" && (
        <Text size="xsmall" className="mt-1 text-ui-fg-subtle">
          Credentials are configured server-side and are never displayed in
          Admin.
        </Text>
      )}
    </DetailRow>
    {connection.auth_mode === "oauth" && (
      <>
        <DetailRow label="Company">
          <Text size="small">
            {connection.company_name ||
              connection.company_id ||
              "Not connected"}
          </Text>
          {connection.company_name && connection.company_id && (
            <Text
              size="xsmall"
              family="mono"
              className="mt-1 break-all text-ui-fg-subtle"
            >
              {connection.company_id}
            </Text>
          )}
        </DetailRow>
        <DetailRow label="Access token renews by">
          <Text size="small">
            {formatDateTime(connection.access_token_expires_at)}
          </Text>
          <Text size="xsmall" className="mt-1 text-ui-fg-subtle">
            Automatic. The connection does not expire from inactivity.
          </Text>
        </DetailRow>
        <DetailRow label="Granted scopes">
          {connection.scopes.length ? (
            <div className="flex flex-wrap gap-1.5">
              {connection.scopes.map((scope) => (
                <Badge key={scope} color="grey" size="xsmall">
                  {scope}
                </Badge>
              ))}
            </div>
          ) : (
            <Text size="small" className="text-ui-fg-subtle">
              No scopes granted
            </Text>
          )}
        </DetailRow>
        <DetailRow label="Connected">
          <Text size="small">{formatDateTime(connection.connected_at)}</Text>
        </DetailRow>
        <DetailRow label="Last updated">
          <Text size="small">{formatDateTime(connection.updated_at)}</Text>
        </DetailRow>
      </>
    )}
  </div>
);

const WebhookDetails = ({ connection }: { connection: MakePayConnection }) => (
  <div className="divide-y">
    <DetailRow label="Webhook health">
      <StatusBadge color={webhookStatusColor(connection.webhook.status)}>
        {humanizeStatus(connection.webhook.status)}
      </StatusBadge>
    </DetailRow>
    <DetailRow label="Callback URL">
      {connection.webhook.callback_url ? (
        <div className="flex min-w-0 items-center gap-x-2">
          <Link aria-hidden="true" className="shrink-0 text-ui-fg-muted" />
          <Text size="small" family="mono" className="break-all">
            {connection.webhook.callback_url}
          </Text>
        </div>
      ) : (
        <Text size="small" className="text-ui-fg-subtle">
          {connection.webhook.configured
            ? "Configured server-side"
            : "Not configured"}
        </Text>
      )}
    </DetailRow>
    {connection.webhook.last_error && (
      <DetailRow label="Webhook error">
        <Text size="small" className="text-ui-fg-error">
          {redactSensitiveText(connection.webhook.last_error)}
        </Text>
      </DetailRow>
    )}
  </div>
);

const MakePaySettingsPage = () => {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const handledCallback = useRef(false);
  const connectionQuery = useQuery({
    queryKey: makePayQueryKeys.connection(),
    queryFn: makePayAdmin.getConnection,
  });

  const connectMutation = useMutation({
    mutationFn: makePayAdmin.startOAuth,
    onSuccess: ({ authorization_url }) => {
      const redirectUrl = safeOAuthRedirect(authorization_url);
      if (!redirectUrl) {
        toast.error("Couldn't connect MakePay", {
          description: "MakePay returned an invalid authorization URL.",
        });
        return;
      }

      window.location.assign(redirectUrl);
    },
    onError: (error) => {
      toast.error("Couldn't connect MakePay", {
        description: getErrorMessage(error),
      });
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: makePayAdmin.disconnect,
    onSuccess: async (response) => {
      queryClient.setQueryData(makePayQueryKeys.connection(), response);
      await queryClient.invalidateQueries({ queryKey: makePayQueryKeys.all });
      if (response.connection.status === "disconnected") {
        toast.success("MakePay disconnected");
      } else {
        toast.warning("MakePay disconnect is pending", {
          description: response.connection.last_error
            ? redactSensitiveText(response.connection.last_error)
            : "MakePay couldn't confirm remote cleanup. Retry disconnect, or reconnect to replace a revoked authorization.",
        });
      }
    },
    onError: (error) => {
      toast.error("Couldn't disconnect MakePay", {
        description: getErrorMessage(error),
      });
    },
  });

  const connection = connectionQuery.data?.connection;
  const capabilities = connectionQuery.data?.capabilities;

  useEffect(() => {
    if (handledCallback.current) {
      return;
    }

    const connected = searchParams.get("makepay_connected") === "1";
    const failed = searchParams.get("makepay_error") === "1";
    if (!connected && !failed) {
      return;
    }

    handledCallback.current = true;
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("makepay_connected");
    nextParams.delete("makepay_error");
    setSearchParams(nextParams, { replace: true });

    if (failed) {
      toast.error("Couldn't connect MakePay", {
        description:
          "Authorization wasn't completed. Review the connection details and try again.",
      });
    } else {
      toast.success("MakePay connected");
    }
  }, [searchParams, setSearchParams]);

  const connectionMutationPending =
    connectMutation.isPending || disconnectMutation.isPending;

  const disconnect = () => {
    if (
      window.confirm(
        "Disconnect MakePay OAuth from this Medusa store? Existing payment records will remain available.",
      )
    ) {
      disconnectMutation.mutate();
    }
  };

  return (
    <div className="flex flex-col gap-y-3" data-testid="makepay-settings-page">
      <Container className="divide-y p-0">
        <div className="flex flex-col gap-y-3 px-6 py-4 sm:flex-row sm:items-start sm:justify-between sm:gap-x-4">
          <div>
            <Heading level="h1">MakePay</Heading>
            <Text size="small" className="mt-1 text-ui-fg-subtle">
              Connect this store to MakeCrypto and monitor hosted crypto
              payments.
            </Text>
          </div>
          {connection && capabilities?.oauth && (
            <div className="flex shrink-0 items-center gap-x-2">
              {connection.status === "disconnect_pending" ? (
                <>
                  <Button
                    variant="secondary"
                    size="small"
                    onClick={() => disconnectMutation.mutate()}
                    isLoading={disconnectMutation.isPending}
                    disabled={connectionMutationPending}
                  >
                    Retry disconnect
                  </Button>
                  <Button
                    size="small"
                    onClick={() => connectMutation.mutate()}
                    isLoading={connectMutation.isPending}
                    disabled={connectionMutationPending}
                  >
                    Reconnect
                  </Button>
                </>
              ) : (
                <>
                  {connection.auth_mode === "oauth" && connection.connected && (
                    <Button
                      variant="secondary"
                      size="small"
                      onClick={disconnect}
                      isLoading={disconnectMutation.isPending}
                      disabled={connectionMutationPending}
                    >
                      Disconnect
                    </Button>
                  )}
                  <Button
                    size="small"
                    onClick={() => connectMutation.mutate()}
                    isLoading={connectMutation.isPending}
                    disabled={connectionMutationPending}
                  >
                    {oauthConnectionActionLabel(connection)}
                  </Button>
                </>
              )}
            </div>
          )}
        </div>

        {connectionQuery.isPending && (
          <div className="flex flex-col gap-y-3 px-6 py-5">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-5 w-72 max-w-full" />
            <Skeleton className="h-5 w-56 max-w-full" />
          </div>
        )}

        {connectionQuery.isError && (
          <div className="px-6 py-5">
            <ErrorNotice message={getErrorMessage(connectionQuery.error)} />
          </div>
        )}

        {connection && <ConnectionDetails connection={connection} />}
      </Container>

      {connection?.last_error && (
        <ErrorNotice
          title={
            connection.reconnect_required
              ? "Reconnect required"
              : "Connection needs attention"
          }
          message={
            connection.reconnect_required &&
            !/reconnect makepay/i.test(connection.last_error)
              ? `${redactSensitiveText(connection.last_error)} Reconnect MakePay to replace this authorization and resume checkout.`
              : redactSensitiveText(connection.last_error)
          }
        />
      )}

      {connection && (
        <Container className="divide-y p-0">
          <div className="px-6 py-4">
            <Heading level="h2">Webhook delivery</Heading>
            <Text size="small" className="mt-1 text-ui-fg-subtle">
              {connection.auth_mode === "oauth"
                ? "MakePay uses signed, installation-scoped webhooks to update Medusa orders."
                : "MakePay uses the signed webhook configured for this payment provider."}
            </Text>
          </div>
          <WebhookDetails connection={connection} />
        </Container>
      )}

      <Container className="flex flex-col gap-y-2 px-6 py-4">
        <Heading level="h2">Payment capabilities</Heading>
        <Text size="small" className="text-ui-fg-subtle">
          {capabilities?.reconcile
            ? "Payment status reconciliation is available. "
            : "Reconciliation requires distributed locking and is currently unavailable. "}
          Merchant-initiated refunds are not supported by MakePay yet and are
          intentionally unavailable here.
        </Text>
        <ExternalLink
          href="https://www.makecrypto.io/documentation/makepay/apps/medusa"
          label="Open the MakePay Medusa setup guide"
        >
          Setup guide
        </ExternalLink>
      </Container>
    </div>
  );
};

export const config = defineRouteConfig({
  label: "MakePay",
  icon: CogSixTooth,
});

export default MakePaySettingsPage;
