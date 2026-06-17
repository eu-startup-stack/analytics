defmodule PlausibleWeb.Plugs.StripAuthentikHeaders do
  @moduledoc """
  Endpoint-level defence-in-depth plug that removes all `x-authentik-*` request
  headers when the request does not come from a trusted Authentik outpost IP.

  Installed in `PlausibleWeb.Endpoint` before `Plug.RequestId` so that spoofed
  headers never reach Sentry context, the router, or any downstream plug.

  When the feature is disabled, `Authentik.trusted_request?/1` returns `false`
  (because `enabled?/0` is false), so the strip always runs. With no
  `x-authentik-*` headers in the request this is a no-op aside from a list scan.
  """

  @behaviour Plug

  alias Plausible.Auth.Authentik

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if Authentik.trusted_request?(conn) do
      conn
    else
      strip(conn)
    end
  end

  defp strip(conn) do
    cleaned =
      Enum.reject(conn.req_headers, fn {k, _v} ->
        String.starts_with?(k, "x-authentik-")
      end)

    %{conn | req_headers: cleaned}
  end
end
