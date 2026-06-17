defmodule PlausibleWeb.Plugs.AuthentikProxy do
  @moduledoc """
  Router-level plug that implements Authentik proxy-header authentication.

  Reads `X-authentik-email`, `X-authentik-name`, and `X-authentik-groups`
  headers (already trust-vetted / stripped by `StripAuthentikHeaders` at the
  endpoint level), JIT-provisions the user if needed, syncs their role on the
  personal team, and establishes or switches the Plausible session.

  Behaviour summary:
  - Feature disabled → no-op (pass through).
  - Feature enabled, untrusted IP → no-op (headers were already stripped by
    the endpoint plug; the request looks anonymous to downstream plugs).
  - Feature enabled, trusted IP, no email header → pass through as anonymous.
  - Feature enabled, trusted IP, email present, no `analytics-*` group → 403.
  - Feature enabled, trusted IP, email present, valid group → provision/get
    user, sync role, establish/switch session.

  Session switching:
  - Same user already logged in → fast path, no rotation.
  - No session → `log_in_user_no_redirect/2`.
  - Different user → `log_out_user/1` (removes old DB session + LV sockets)
    then `log_in_user_no_redirect/2`.
  """

  @behaviour Plug

  require Logger

  import Plug.Conn

  alias Plausible.Auth.Authentik
  alias PlausibleWeb.UserAuth

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    cond do
      not Authentik.enabled?() ->
        conn

      not Authentik.trusted_request?(conn) ->
        # Headers were already stripped by the endpoint plug; nothing to do.
        conn

      true ->
        apply_identity(conn)
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp apply_identity(conn) do
    email = conn |> header("x-authentik-email") |> normalise_email()
    name = header(conn, "x-authentik-name")
    groups = header(conn, "x-authentik-groups")

    cond do
      is_nil(email) ->
        # Trusted source said nothing about a user. Pass through as anonymous.
        # (The outpost is supposed to inject headers; absent headers are an
        # outpost misconfiguration, not an attack.)
        conn

      true ->
        case Authentik.role_from_groups(groups) do
          :error ->
            conn
            |> send_resp(403, "Forbidden: missing required analytics-* group")
            |> halt()

          {:ok, role} ->
            with {:ok, user} <- Authentik.provision_or_get(email, name),
                 :ok <- Authentik.sync_role(user, role) do
              maybe_switch_session(conn, user)
            else
              {:error, cs} ->
                Logger.error(
                  "authentik: failed to provision user #{inspect(email)}: #{inspect(cs.errors)}"
                )

                conn
                |> send_resp(500, "Authentication backend error")
                |> halt()
            end
        end
    end
  end

  defp maybe_switch_session(conn, user) do
    current_id = current_user_id_from_session(conn)

    cond do
      current_id == user.id ->
        # Fast path: already logged in as this user. No rotation needed.
        conn

      is_nil(current_id) ->
        UserAuth.log_in_user_no_redirect(conn, user)

      true ->
        # Identity change: log out the old user (removes DB session row and
        # disconnects LiveView sockets), then log in the new user.
        conn
        |> UserAuth.log_out_user()
        |> UserAuth.log_in_user_no_redirect(user)
    end
  end

  defp current_user_id_from_session(conn) do
    case UserAuth.get_user_session(conn) do
      {:ok, session} -> session.user_id
      _ -> nil
    end
  end

  defp header(conn, name) do
    conn |> get_req_header(name) |> List.first()
  end

  defp normalise_email(nil), do: nil

  defp normalise_email(s) do
    trimmed = s |> String.trim() |> String.downcase()
    if trimmed == "", do: nil, else: trimmed
  end
end
