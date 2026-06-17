defmodule PlausibleWeb.Plugs.StripAuthentikHeadersTest do
  # async: false because we mutate Application env
  use ExUnit.Case, async: false

  alias PlausibleWeb.Plugs.StripAuthentikHeaders

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_conn_with_headers(headers) do
    conn = Plug.Test.conn(:get, "/")

    Enum.reduce(headers, conn, fn {k, v}, c ->
      Plug.Conn.put_req_header(c, k, v)
    end)
  end

  defp set_authentik_config(opts) do
    original = Application.get_env(:plausible, :authentik_proxy)

    Application.put_env(:plausible, :authentik_proxy, opts)

    on_exit(fn ->
      if original do
        Application.put_env(:plausible, :authentik_proxy, original)
      else
        Application.delete_env(:plausible, :authentik_proxy)
      end
    end)
  end

  defp has_header?(conn, name) do
    Enum.any?(conn.req_headers, fn {k, _} -> k == name end)
  end

  # ---------------------------------------------------------------------------
  # Tests
  # ---------------------------------------------------------------------------

  test "feature disabled: strips x-authentik-* headers from any remote_ip (defence-in-depth)" do
    set_authentik_config(enabled: false, trusted_cidrs: [], group_prefix: "analytics-")

    conn =
      build_conn_with_headers([
        {"x-authentik-username", "alice"},
        {"x-authentik-email", "alice@example.com"},
        {"x-foo", "bar"}
      ])
      |> Map.put(:remote_ip, {8, 8, 8, 8})

    result = StripAuthentikHeaders.call(conn, [])

    refute has_header?(result, "x-authentik-username")
    refute has_header?(result, "x-authentik-email")
    # Non-authentik header preserved
    assert has_header?(result, "x-foo")
  end

  test "feature enabled, trusted IP: headers preserved" do
    set_authentik_config(
      enabled: true,
      trusted_cidrs: [{{127, 0, 0, 0}, 8}],
      group_prefix: "analytics-"
    )

    conn =
      build_conn_with_headers([
        {"x-authentik-email", "alice@example.com"},
        {"x-authentik-groups", "analytics-admin"}
      ])
      |> Map.put(:remote_ip, {127, 0, 0, 1})

    result = StripAuthentikHeaders.call(conn, [])

    assert has_header?(result, "x-authentik-email")
    assert has_header?(result, "x-authentik-groups")
  end

  test "feature enabled, untrusted IP: headers removed" do
    set_authentik_config(
      enabled: true,
      trusted_cidrs: [{{127, 0, 0, 0}, 8}],
      group_prefix: "analytics-"
    )

    conn =
      build_conn_with_headers([
        {"x-authentik-email", "alice@example.com"},
        {"x-authentik-groups", "analytics-admin"}
      ])
      |> Map.put(:remote_ip, {8, 8, 8, 8})

    result = StripAuthentikHeaders.call(conn, [])

    refute has_header?(result, "x-authentik-email")
    refute has_header?(result, "x-authentik-groups")
  end

  test "feature enabled, IPv6-mapped IPv4 (::ffff:127.0.0.1), trusted CIDR 127.0.0.0/8: headers preserved" do
    set_authentik_config(
      enabled: true,
      trusted_cidrs: [{{127, 0, 0, 0}, 8}],
      group_prefix: "analytics-"
    )

    # ::ffff:127.0.0.1 as an 8-tuple
    v6_mapped = {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}

    conn =
      build_conn_with_headers([{"x-authentik-email", "alice@example.com"}])
      |> Map.put(:remote_ip, v6_mapped)

    result = StripAuthentikHeaders.call(conn, [])

    assert has_header?(result, "x-authentik-email")
  end

  test "feature enabled, IPv6 ::1, trusted CIDR ::1/128: headers preserved" do
    set_authentik_config(
      enabled: true,
      trusted_cidrs: [{{0, 0, 0, 0, 0, 0, 0, 1}, 128}],
      group_prefix: "analytics-"
    )

    conn =
      build_conn_with_headers([{"x-authentik-email", "alice@example.com"}])
      |> Map.put(:remote_ip, {0, 0, 0, 0, 0, 0, 0, 1})

    result = StripAuthentikHeaders.call(conn, [])

    assert has_header?(result, "x-authentik-email")
  end

  test "multiple x-authentik-* headers and a non-authentik header: only authentik ones removed" do
    set_authentik_config(
      enabled: true,
      trusted_cidrs: [{{127, 0, 0, 0}, 8}],
      group_prefix: "analytics-"
    )

    conn =
      build_conn_with_headers([
        {"x-authentik-email", "alice@example.com"},
        {"x-authentik-name", "Alice"},
        {"x-authentik-groups", "analytics-admin"},
        {"x-foo", "keep-me"},
        {"authorization", "Bearer token"}
      ])
      |> Map.put(:remote_ip, {8, 8, 8, 8})

    result = StripAuthentikHeaders.call(conn, [])

    refute has_header?(result, "x-authentik-email")
    refute has_header?(result, "x-authentik-name")
    refute has_header?(result, "x-authentik-groups")
    assert has_header?(result, "x-foo")
    assert has_header?(result, "authorization")
  end
end
