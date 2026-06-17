defmodule Plausible.Auth.Authentik do
  @moduledoc """
  Support module for Authentik proxy-header authentication.

  Provides:
  - Feature config accessors (`enabled?/0`, `trusted_cidrs/0`, `group_prefix/0`, `trusted_request?/1`)
  - `role_from_groups/1` — maps pipe-separated Authentik group names to a Plausible role atom
  - `provision_or_get/2` — race-safe JIT user creation + personal-team creation
  - `sync_role/2` — upserts the personal-team membership at the target role with owner-lock semantics
  - CIDR helpers `parse_cidr!/1`, `in_any_cidr?/2` with IPv6-mapped-IPv4 normalisation

  This module is CE-only. It lives in `lib/` and must not reference anything in `extra/lib/`.
  """

  require Logger
  import Bitwise

  alias Plausible.{Auth, Repo, Teams}
  alias Plausible.Teams.Membership

  # Map header suffix (after stripping the configured prefix) -> Plausible role atom.
  # Using a hardcoded map is safer than String.to_existing_atom/1 because unknown
  # suffixes are silently dropped rather than potentially raising ArgumentError.
  @group_to_role %{
    "viewer" => :viewer,
    "editor" => :editor,
    "admin" => :admin,
    "billing" => :billing,
    "owner" => :owner
  }

  # Highest privilege first. The first match in this list wins.
  @role_priority [:owner, :admin, :editor, :billing, :viewer]

  # ---------------------------------------------------------------------------
  # Config accessors
  # ---------------------------------------------------------------------------

  @doc "Returns the full `:authentik_proxy` keyword config."
  def config, do: Application.get_env(:plausible, :authentik_proxy, [])

  @doc "Returns `true` when Authentik proxy auth is enabled."
  def enabled?, do: Keyword.get(config(), :enabled, false)

  @doc "Returns the list of parsed trusted CIDR tuples `{ip_tuple, prefix_len}`."
  def trusted_cidrs, do: Keyword.get(config(), :trusted_cidrs, [])

  @doc "Returns the group prefix string (default `\"analytics-\"`)."
  def group_prefix, do: Keyword.get(config(), :group_prefix, "analytics-")

  @doc """
  Returns `true` when the feature is enabled AND `conn.remote_ip` matches one of
  the configured trusted CIDRs.

  Returns `false` in all other cases, including when the feature is disabled.
  """
  @spec trusted_request?(Plug.Conn.t()) :: boolean()
  def trusted_request?(%Plug.Conn{} = conn) do
    enabled?() and in_any_cidr?(conn.remote_ip, trusted_cidrs())
  end

  # ---------------------------------------------------------------------------
  # Role mapping
  # ---------------------------------------------------------------------------

  @doc """
  Maps a pipe-separated Authentik groups string to the highest-privilege Plausible role.

  Returns `{:ok, role_atom}` or `:error` (no matching `analytics-*` group found).

  ## Examples

      iex> role_from_groups("analytics-admin|analytics-viewer")
      {:ok, :admin}

      iex> role_from_groups("unrelated|other")
      :error

      iex> role_from_groups(nil)
      :error
  """
  @spec role_from_groups(String.t() | nil) :: {:ok, atom()} | :error
  def role_from_groups(nil), do: :error
  def role_from_groups(""), do: :error

  def role_from_groups(groups_str) when is_binary(groups_str) do
    prefix = group_prefix()

    matched =
      groups_str
      |> String.split("|", trim: true)
      |> Enum.flat_map(fn g ->
        case String.split(g, prefix, parts: 2) do
          ["", suffix] -> List.wrap(Map.get(@group_to_role, suffix))
          _ -> []
        end
      end)
      |> MapSet.new()

    case Enum.find(@role_priority, &MapSet.member?(matched, &1)) do
      nil -> :error
      role -> {:ok, role}
    end
  end

  # ---------------------------------------------------------------------------
  # JIT provisioning
  # ---------------------------------------------------------------------------

  @doc """
  Returns an existing user by email, or JIT-provisions a new one.

  On first sight:
  1. Inserts a new `Auth.User` with a random unusable password and `email_verified: true`.
  2. Calls `Teams.get_or_create/1` to create the personal team.

  Race-safe: if a concurrent request already inserted the same email, the unique
  constraint violation is detected and the pre-existing user is returned.

  Returns `{:ok, user}` or `{:error, changeset}` on unexpected DB errors.
  """
  @spec provision_or_get(String.t(), String.t() | nil) ::
          {:ok, Auth.User.t()} | {:error, Ecto.Changeset.t()}
  def provision_or_get(email, name) when is_binary(email) do
    case Repo.get_by(Auth.User, email: email) do
      %Auth.User{} = u ->
        {:ok, u}

      nil ->
        case Repo.insert(jit_changeset(email, name)) do
          {:ok, user} ->
            {:ok, _team} = Teams.get_or_create(user)
            {:ok, user}

          {:error, cs} ->
            if unique_email_violation?(cs) do
              # Lost the race: another concurrent request already created this user.
              {:ok, Repo.get_by!(Auth.User, email: email)}
            else
              {:error, cs}
            end
        end
    end
  end

  defp jit_changeset(email, name) do
    random_password = :crypto.strong_rand_bytes(64) |> Base.encode64(padding: false)

    %Auth.User{}
    |> Ecto.Changeset.cast(%{email: email, name: name || email}, [:email, :name])
    |> Ecto.Changeset.validate_required([:email, :name])
    |> Ecto.Changeset.put_change(:password_hash, Auth.Password.hash(random_password))
    |> Ecto.Changeset.put_change(:email_verified, true)
    |> Ecto.Changeset.unique_constraint(:email)
  end

  defp unique_email_violation?(%Ecto.Changeset{errors: errors}) do
    Enum.any?(errors, fn
      {:email, {_msg, attrs}} -> {:constraint, :unique} in attrs
      _ -> false
    end)
  end

  # ---------------------------------------------------------------------------
  # Role sync
  # ---------------------------------------------------------------------------

  @doc """
  Ensures the user's personal-team membership is at `target_role`.

  Owner-lock: if the current membership role is `:owner`, it is never downgraded.
  A `Logger.info/1` line is emitted when the lock fires.

  Returns `:ok`.
  """
  @spec sync_role(Auth.User.t(), atom()) :: :ok
  def sync_role(%Auth.User{} = user, target_role) when is_atom(target_role) do
    {:ok, team} = Teams.get_or_create(user)

    case Repo.get_by(Membership, user_id: user.id, team_id: team.id) do
      nil ->
        # Defensive: get_or_create should have created the owner membership.
        # If somehow missing, insert at target_role.
        Membership.changeset(team, user, target_role) |> Repo.insert!()

      %Membership{role: ^target_role} ->
        # Already at the correct role — no-op.
        :ok

      %Membership{role: :owner} ->
        # Personal-team owner. Never downgrade: that would orphan the team.
        Logger.info(
          "authentik: not changing role of personal-team owner (user_id=#{user.id})"
        )

        :ok

      %Membership{} = m ->
        m |> Ecto.Changeset.change(role: target_role) |> Repo.update!()
    end

    :ok
  end

  # ---------------------------------------------------------------------------
  # CIDR helpers
  # ---------------------------------------------------------------------------

  @doc """
  Parses a CIDR string like `"10.0.0.0/8"` or `"::1/128"` into `{ip_tuple, prefix_len}`.

  Raises on invalid input (bad IP, bad prefix, prefix out of range).
  """
  @spec parse_cidr!(String.t()) :: {:inet.ip_address(), non_neg_integer()}
  def parse_cidr!(str) when is_binary(str) do
    case String.split(str, "/", parts: 2) do
      [ip_str, prefix_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, ip} ->
            case Integer.parse(prefix_str) do
              {prefix, ""} ->
                max = if tuple_size(ip) == 4, do: 32, else: 128

                unless prefix in 0..max do
                  raise ArgumentError, "Invalid CIDR prefix #{prefix} in #{str}"
                end

                {ip, prefix}

              _ ->
                raise ArgumentError, "Invalid CIDR prefix in #{str}"
            end

          {:error, _} ->
            raise ArgumentError, "Invalid IP address in CIDR #{str}"
        end

      _ ->
        raise ArgumentError, "Invalid CIDR format (missing /): #{str}"
    end
  end

  @doc "Returns `true` if `ip` matches any CIDR in the list."
  @spec in_any_cidr?(:inet.ip_address(), list()) :: boolean()
  def in_any_cidr?(_ip, []), do: false
  def in_any_cidr?(ip, cidrs), do: Enum.any?(cidrs, &in_cidr?(ip, &1))

  defp in_cidr?(ip, {cidr_ip, prefix}) do
    ip = normalise_v4mapped(ip)
    cidr_ip = normalise_v4mapped(cidr_ip)

    cond do
      tuple_size(ip) != tuple_size(cidr_ip) ->
        false

      tuple_size(ip) == 4 ->
        bit_match(ip_to_int(ip, 32), ip_to_int(cidr_ip, 32), 32 - prefix)

      true ->
        bit_match(ip_to_int(ip, 128), ip_to_int(cidr_ip, 128), 128 - prefix)
    end
  end

  # Normalise IPv6-mapped IPv4 addresses (::ffff:a.b.c.d) to their IPv4 form.
  # Cowboy on dual-stack listeners may deliver IPv4 peers as {0,0,0,0,0,0xffff,a,b}.
  defp normalise_v4mapped({0, 0, 0, 0, 0, 0xFFFF, a, b}) do
    {a >>> 8, a &&& 0xFF, b >>> 8, b &&& 0xFF}
  end

  defp normalise_v4mapped(ip), do: ip

  defp ip_to_int({a, b, c, d}, 32) do
    (a <<< 24) + (b <<< 16) + (c <<< 8) + d
  end

  defp ip_to_int({a, b, c, d, e, f, g, h}, 128) do
    (a <<< 112) + (b <<< 96) + (c <<< 80) + (d <<< 64) +
      (e <<< 48) + (f <<< 32) + (g <<< 16) + h
  end

  defp bit_match(_, _, shift) when shift < 0, do: false
  defp bit_match(x, y, shift), do: (x >>> shift) == (y >>> shift)
end
