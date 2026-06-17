defmodule PlausibleWeb.Plugs.AuthentikProxyTest do
  # async: false because we mutate Application env
  use PlausibleWeb.ConnCase, async: false

  import Ecto.Query

  alias Plausible.Auth.Authentik
  alias Plausible.Auth.UserSession
  alias Plausible.Repo
  alias Plausible.Teams
  alias Plausible.Teams.Membership
  alias PlausibleWeb.Plugs.AuthentikProxy
  alias PlausibleWeb.Plugs.StripAuthentikHeaders
  alias PlausibleWeb.UserAuth

  # ---------------------------------------------------------------------------
  # Config helpers
  # ---------------------------------------------------------------------------

  defp enable_authentik(trusted_cidrs \\ [{{127, 0, 0, 0}, 8}]) do
    original = Application.get_env(:plausible, :authentik_proxy)

    Application.put_env(:plausible, :authentik_proxy,
      enabled: true,
      trusted_cidrs: trusted_cidrs,
      group_prefix: "analytics-"
    )

    on_exit(fn ->
      if original do
        Application.put_env(:plausible, :authentik_proxy, original)
      else
        Application.delete_env(:plausible, :authentik_proxy)
      end
    end)
  end

  defp disable_authentik do
    original = Application.get_env(:plausible, :authentik_proxy)

    Application.put_env(:plausible, :authentik_proxy,
      enabled: false,
      trusted_cidrs: [],
      group_prefix: "analytics-"
    )

    on_exit(fn ->
      if original do
        Application.put_env(:plausible, :authentik_proxy, original)
      else
        Application.delete_env(:plausible, :authentik_proxy)
      end
    end)
  end

  # Build a conn with a session (needed for session operations)
  defp build_conn_with_session(remote_ip \\ {127, 0, 0, 1}) do
    build_conn(:get, "/")
    |> init_session()
    |> Map.put(:remote_ip, remote_ip)
  end

  defp add_authentik_headers(conn, email, name \\ "Test User", groups \\ "analytics-admin") do
    conn
    |> Plug.Conn.put_req_header("x-authentik-email", email)
    |> Plug.Conn.put_req_header("x-authentik-name", name)
    |> Plug.Conn.put_req_header("x-authentik-groups", groups)
  end

  defp session_count_for(user) do
    Repo.aggregate(
      from(us in UserSession, where: us.user_id == ^user.id),
      :count
    )
  end

  # ---------------------------------------------------------------------------
  # A. Disabled (default)
  # ---------------------------------------------------------------------------

  describe "A. feature disabled" do
    test "plug is a no-op: no DB writes, conn unchanged" do
      disable_authentik()

      email = "disabled-#{System.unique_integer()}@example.com"

      conn =
        build_conn_with_session()
        |> add_authentik_headers(email)
        |> AuthentikProxy.call([])

      # No user created
      assert is_nil(Repo.get_by(Plausible.Auth.User, email: email))
      # Conn not halted
      refute conn.halted
    end
  end

  # ---------------------------------------------------------------------------
  # B. Enabled, untrusted IP
  # ---------------------------------------------------------------------------

  describe "B. enabled, untrusted IP" do
    test "plug returns conn unchanged, no user created" do
      enable_authentik([{{127, 0, 0, 0}, 8}])

      email = "untrusted-#{System.unique_integer()}@example.com"

      conn =
        build_conn_with_session({8, 8, 8, 8})
        |> add_authentik_headers(email)
        |> AuthentikProxy.call([])

      assert is_nil(Repo.get_by(Plausible.Auth.User, email: email))
      refute conn.halted
    end
  end

  # ---------------------------------------------------------------------------
  # C. Enabled, trusted IP, valid group, new user
  # ---------------------------------------------------------------------------

  describe "C. enabled, trusted IP, valid group, new user" do
    test "JIT-provisions user, creates personal team, establishes session" do
      enable_authentik()

      email = "jit-#{System.unique_integer()}@example.com"
      name = "JIT User"

      conn =
        build_conn_with_session()
        |> add_authentik_headers(email, name, "analytics-viewer")
        |> AuthentikProxy.call([])

      refute conn.halted

      # User persisted
      user = Repo.get_by!(Plausible.Auth.User, email: email)
      assert user.email_verified == true
      assert user.name == name

      # Personal team membership exists (owner-lock applies: viewer group → owner stays)
      {:ok, team} = Teams.get_or_create(user)
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert membership.role == :owner

      # Server-side session row exists
      assert session_count_for(user) >= 1

      # Session token set in conn
      token = Plug.Conn.get_session(conn, :user_token)
      assert is_binary(token)
    end

    test "email header is downcased before lookup/insert" do
      enable_authentik()

      conn =
        build_conn_with_session()
        |> add_authentik_headers("Alice@Example.COM", "Alice", "analytics-admin")
        |> AuthentikProxy.call([])

      refute conn.halted

      # Stored with downcased email
      assert Repo.get_by(Plausible.Auth.User, email: "alice@example.com")
      assert is_nil(Repo.get_by(Plausible.Auth.User, email: "Alice@Example.COM"))
    end
  end

  # ---------------------------------------------------------------------------
  # D. Enabled, trusted IP, existing user, group changed
  # ---------------------------------------------------------------------------

  describe "D. enabled, trusted IP, existing user, group changed" do
    test "updates non-owner membership to new role" do
      enable_authentik()

      user = new_user()
      {:ok, team} = Teams.get_or_create(user)

      # Manually set membership to :editor
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)

      membership
      |> Ecto.Changeset.change(role: :editor)
      |> Repo.update!()

      conn =
        build_conn_with_session()
        |> add_authentik_headers(user.email, user.name, "analytics-admin")
        |> AuthentikProxy.call([])

      refute conn.halted

      updated = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert updated.role == :admin
    end
  end

  # ---------------------------------------------------------------------------
  # E. Enabled, trusted IP, no analytics-* group → 403
  # ---------------------------------------------------------------------------

  describe "E. enabled, trusted IP, no analytics-* group" do
    test "returns 403, halted, no user created, no session" do
      enable_authentik()

      email = "no-group-#{System.unique_integer()}@example.com"

      conn =
        build_conn_with_session()
        |> add_authentik_headers(email, "No Group User", "unrelated-group|other-group")
        |> AuthentikProxy.call([])

      assert conn.halted
      assert conn.status == 403
      assert is_nil(Repo.get_by(Plausible.Auth.User, email: email))
    end
  end

  # ---------------------------------------------------------------------------
  # F. Identity switch: logged in as A, request for B
  # ---------------------------------------------------------------------------

  describe "F. identity switch" do
    test "A's session deleted, B gets new session, conn token points to B" do
      enable_authentik()

      user_a = new_user()
      user_b = new_user()

      # Establish session for A
      conn_a =
        build_conn_with_session()
        |> UserAuth.log_in_user_no_redirect(user_a)

      # Verify A has a session
      assert session_count_for(user_a) == 1
      token_a = Plug.Conn.get_session(conn_a, :user_token)

      # Now send request with B's headers (conn carries A's session)
      conn_b =
        conn_a
        |> add_authentik_headers(user_b.email, user_b.name, "analytics-admin")
        |> AuthentikProxy.call([])

      refute conn_b.halted

      # A's session row should be deleted
      assert session_count_for(user_a) == 0

      # B has a session row
      assert session_count_for(user_b) >= 1

      # Conn session token points to B's session (not A's)
      token_b = Plug.Conn.get_session(conn_b, :user_token)
      assert is_binary(token_b)
      refute token_b == token_a
    end
  end

  # ---------------------------------------------------------------------------
  # G. Same user already logged in → no rotation
  # ---------------------------------------------------------------------------

  describe "G. same user already logged in" do
    test "session row count unchanged, token unchanged" do
      enable_authentik()

      user = new_user()

      conn =
        build_conn_with_session()
        |> UserAuth.log_in_user_no_redirect(user)

      assert session_count_for(user) == 1
      token_before = Plug.Conn.get_session(conn, :user_token)

      conn2 =
        conn
        |> add_authentik_headers(user.email, user.name, "analytics-admin")
        |> AuthentikProxy.call([])

      refute conn2.halted
      assert session_count_for(user) == 1
      assert Plug.Conn.get_session(conn2, :user_token) == token_before
    end
  end

  # ---------------------------------------------------------------------------
  # H. Strip plug + AuthentikProxy together: untrusted IP with spoofed headers
  # ---------------------------------------------------------------------------

  describe "H. strip plug + proxy together, untrusted IP" do
    test "no user created, no 403, conn passes through anonymous" do
      enable_authentik()

      email = "spoofed-#{System.unique_integer()}@example.com"

      conn =
        build_conn_with_session({8, 8, 8, 8})
        |> add_authentik_headers(email, "Spoofer", "analytics-admin")
        |> StripAuthentikHeaders.call([])
        |> AuthentikProxy.call([])

      refute conn.halted
      assert is_nil(Repo.get_by(Plausible.Auth.User, email: email))
      # No session token set
      assert is_nil(Plug.Conn.get_session(conn, :user_token))
    end
  end
end
