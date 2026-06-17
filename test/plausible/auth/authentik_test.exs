defmodule Plausible.Auth.AuthentikTest do
  use Plausible.DataCase, async: false

  import ExUnit.CaptureLog

  alias Plausible.Auth.Authentik
  alias Plausible.Auth.User
  alias Plausible.Repo
  alias Plausible.Teams
  alias Plausible.Teams.Membership

  # ---------------------------------------------------------------------------
  # A. role_from_groups/1
  # ---------------------------------------------------------------------------

  describe "role_from_groups/1" do
    test "nil returns :error" do
      assert :error = Authentik.role_from_groups(nil)
    end

    test "empty string returns :error" do
      assert :error = Authentik.role_from_groups("")
    end

    test "unrelated groups return :error" do
      assert :error = Authentik.role_from_groups("unrelated|other")
    end

    test "analytics-viewer returns {:ok, :viewer}" do
      assert {:ok, :viewer} = Authentik.role_from_groups("analytics-viewer")
    end

    test "analytics-admin returns {:ok, :admin}" do
      assert {:ok, :admin} = Authentik.role_from_groups("analytics-admin")
    end

    test "analytics-viewer|analytics-admin returns {:ok, :admin} (highest wins)" do
      assert {:ok, :admin} = Authentik.role_from_groups("analytics-viewer|analytics-admin")
    end

    test "analytics-owner|analytics-viewer returns {:ok, :owner} (highest wins)" do
      assert {:ok, :owner} = Authentik.role_from_groups("analytics-owner|analytics-viewer")
    end

    test "analytics-superuser (unknown suffix) returns :error" do
      assert :error = Authentik.role_from_groups("analytics-superuser")
    end

    test "foo|analytics-editor|bar returns {:ok, :editor}" do
      assert {:ok, :editor} = Authentik.role_from_groups("foo|analytics-editor|bar")
    end

    test "analytics-billing returns {:ok, :billing}" do
      assert {:ok, :billing} = Authentik.role_from_groups("analytics-billing")
    end
  end

  # ---------------------------------------------------------------------------
  # B. provision_or_get/2
  # ---------------------------------------------------------------------------

  describe "provision_or_get/2" do
    test "new email: creates user with email_verified=true and personal team" do
      email = "new-jit-#{System.unique_integer()}@example.com"
      name = "JIT User"

      assert {:ok, user} = Authentik.provision_or_get(email, name)

      assert user.email == email
      assert user.name == name
      assert user.email_verified == true

      # Personal team membership should exist
      {:ok, team} = Teams.get_or_create(user)
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert membership.role == :owner
    end

    test "existing email: returns existing user without re-inserting" do
      user = insert(:user)
      original_id = user.id

      assert {:ok, returned_user} = Authentik.provision_or_get(user.email, "Different Name")

      assert returned_user.id == original_id
      # Name should NOT be updated (we just return the existing user)
      assert returned_user.email == user.email
    end

    test "race condition: inserting same email twice returns pre-existing user" do
      email = "race-#{System.unique_integer()}@example.com"

      # First call creates the user
      assert {:ok, user1} = Authentik.provision_or_get(email, "First")

      # Second call should find the existing user (simulates the refetch path)
      assert {:ok, user2} = Authentik.provision_or_get(email, "Second")

      assert user1.id == user2.id
    end

    test "name defaults to email when nil" do
      email = "no-name-#{System.unique_integer()}@example.com"

      assert {:ok, user} = Authentik.provision_or_get(email, nil)

      assert user.name == email
    end
  end

  # ---------------------------------------------------------------------------
  # C. sync_role/2
  # ---------------------------------------------------------------------------

  describe "sync_role/2" do
    test "personal-team owner: sync_role with :viewer keeps :owner (owner-lock) and logs" do
      user = new_user()
      {:ok, team} = Teams.get_or_create(user)
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert membership.role == :owner

      log =
        capture_log(fn ->
          assert :ok = Authentik.sync_role(user, :viewer)
        end)

      assert log =~ "not changing role of personal-team owner"

      # Membership unchanged
      updated = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert updated.role == :owner
    end

    test "personal-team owner: sync_role with :admin also triggers owner-lock" do
      user = new_user()
      {:ok, team} = Teams.get_or_create(user)

      log =
        capture_log(fn ->
          assert :ok = Authentik.sync_role(user, :admin)
        end)

      assert log =~ "not changing role of personal-team owner"

      updated = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert updated.role == :owner
    end

    test "non-owner membership: sync_role updates to target role" do
      user = new_user()
      {:ok, team} = Teams.get_or_create(user)

      # Manually change the membership to :editor (bypassing the personal-team default)
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)

      membership
      |> Ecto.Changeset.change(role: :editor)
      |> Repo.update!()

      assert :ok = Authentik.sync_role(user, :admin)

      updated = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert updated.role == :admin
    end

    test "sync_role when current role matches target: no-op, no log" do
      user = new_user()
      {:ok, team} = Teams.get_or_create(user)

      # Change to :editor first
      membership = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)

      membership
      |> Ecto.Changeset.change(role: :editor)
      |> Repo.update!()

      log =
        capture_log(fn ->
          assert :ok = Authentik.sync_role(user, :editor)
        end)

      # No log line emitted for no-op
      refute log =~ "not changing role"

      updated = Repo.get_by!(Membership, user_id: user.id, team_id: team.id)
      assert updated.role == :editor
    end
  end

  # ---------------------------------------------------------------------------
  # D. CIDR helpers
  # ---------------------------------------------------------------------------

  describe "parse_cidr!/1" do
    test "parses IPv4 /32" do
      assert {{127, 0, 0, 1}, 32} = Authentik.parse_cidr!("127.0.0.1/32")
    end

    test "parses IPv4 /8" do
      assert {{10, 0, 0, 0}, 8} = Authentik.parse_cidr!("10.0.0.0/8")
    end

    test "parses IPv6 /128" do
      assert {{0, 0, 0, 0, 0, 0, 0, 1}, 128} = Authentik.parse_cidr!("::1/128")
    end

    test "parses IPv6 /32" do
      {ip, 32} = Authentik.parse_cidr!("2001:db8::/32")
      assert tuple_size(ip) == 8
    end

    test "raises on garbage input" do
      assert_raise ArgumentError, fn -> Authentik.parse_cidr!("garbage") end
    end

    test "raises on invalid prefix (too large for IPv4)" do
      assert_raise ArgumentError, fn -> Authentik.parse_cidr!("10.0.0.0/33") end
    end

    test "raises on invalid prefix (too large for IPv6)" do
      assert_raise ArgumentError, fn -> Authentik.parse_cidr!("::1/129") end
    end
  end

  describe "in_any_cidr?/2" do
    test "IPv4 match within /8" do
      assert Authentik.in_any_cidr?({127, 0, 0, 1}, [{{127, 0, 0, 0}, 8}])
    end

    test "IPv4 no match" do
      refute Authentik.in_any_cidr?({192, 168, 1, 1}, [{{10, 0, 0, 0}, 8}])
    end

    test "IPv6 exact match /128" do
      assert Authentik.in_any_cidr?({0, 0, 0, 0, 0, 0, 0, 1}, [{{0, 0, 0, 0, 0, 0, 0, 1}, 128}])
    end

    test "IPv6-mapped IPv4 normalised to IPv4 CIDR" do
      # ::ffff:127.0.0.1 should match 127.0.0.0/8
      v6_mapped = {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}
      assert Authentik.in_any_cidr?(v6_mapped, [{{127, 0, 0, 0}, 8}])
    end

    test "empty CIDR list returns false" do
      refute Authentik.in_any_cidr?({192, 168, 1, 1}, [])
    end

    test "mismatched family (IPv4 against IPv6 CIDR) returns false" do
      refute Authentik.in_any_cidr?({192, 168, 1, 1}, [{{0, 0, 0, 0, 0, 0, 0, 1}, 128}])
    end

    test "IPv4 /32 exact match" do
      assert Authentik.in_any_cidr?({10, 0, 0, 1}, [{{10, 0, 0, 1}, 32}])
    end

    test "IPv4 /32 no match for different address" do
      refute Authentik.in_any_cidr?({10, 0, 0, 2}, [{{10, 0, 0, 1}, 32}])
    end
  end
end
