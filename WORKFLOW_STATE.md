# WORKFLOW_STATE

Task: Switch Plausible CE authentication to Authentik proxy-header auth with JIT user provisioning and group→role mapping.

Status: Plan v2 finalised after debater revisions. Task briefs ready below.

Next Agent: claude-implementor (start with Task 1)

---

## Scope (agreed)

### Requirements
1. App sits behind an Authentik Proxy Provider outpost which injects `X-authentik-*` headers for authenticated users.
2. On every request to a browser-authenticated route in CE builds (when feature is enabled):
   - Trust `X-authentik-*` headers **only** when the request's `remote_ip` is in a configured trusted-proxy CIDR list. Otherwise strip them and fall through as anonymous.
   - Identify the user by `X-authentik-email` (case-insensitive match against `users.email`). `X-authentik-username` and `X-authentik-uid` are not used as primary key because Plausible's User schema keys on email.
   - JIT-provision the user on first sight using `X-authentik-email` + `X-authentik-name` (random unusable password; `email_verified: true`). Auto-create a personal team via the existing `Plausible.Teams.get_or_create/1`.
   - Compute the user's effective role from `X-authentik-groups` (pipe-separated). Strip the `analytics-` prefix, map remainder → membership role. Highest privilege wins. Apply the role to the user's personal team membership; if changed, UPDATE the row.
   - If no `analytics-*` group is present, **reject the request (403)**.
3. Replace the local login UI: when Authentik mode is enabled, the `/login`, `/register`, `/password/*`, `/2fa/*`, `/activate*` routes redirect to `/` (the proxy will gate them anyway, but we explicitly skip the local UI).
4. The Authentik header path establishes the same Plausible session that `PlausibleWeb.UserAuth.log_in_user/3` would create. Existing `AuthPlug` / `current_user` / `current_team` / `current_team_role` semantics keep working unchanged.

### Constraints
- CE build only. Use `lib/` only (not `extra/lib/`). Do NOT touch `on_ee` macros — they are already false in CE.
- No physical removal of EE code; the diff should remain mergeable with upstream `plausible/analytics`.
- Source-only change. No live Authentik/database/runtime available. Tests are static (ExUnit unit tests using `Plug.Test` + the existing `ConnCase`).
- Feature must default to OFF. When OFF, the codebase behaves identically to upstream CE (existing login UI, sessions, etc.). Controlled by `AUTHENTIK_PROXY_ENABLED` env var.
- Group→role mapping uses the `analytics-` prefix only; configurable later but hardcoded for now per operator decision.

### Success criteria
- With `AUTHENTIK_PROXY_ENABLED=false`: existing test suite (`mix test`, `MIX_ENV=ce_test mix test`) passes unchanged — i.e. we don't regress anything.
- With `AUTHENTIK_PROXY_ENABLED=true` plus trusted-proxy CIDR set:
  - A request with no `X-authentik-*` headers from an untrusted IP is treated as anonymous (no headers trusted).
  - A request with `X-authentik-*` headers from an untrusted IP has those headers stripped (no spoofing succeeds).
  - A request with `X-authentik-*` headers from a trusted IP:
    - Existing user, group `analytics-admin`: session established, `current_user.email` matches, role on personal team is `:admin`.
    - New user: JIT-creates `Auth.User` + personal team + membership at the mapped role.
    - User in groups `analytics-viewer|analytics-admin`: ends up with `:admin` (highest wins).
    - User with no `analytics-*` group: 403 response, no session created, no user record created.
- Inbound spoofed `X-authentik-*` headers from a non-trusted client IP never affect `conn.assigns.current_user`.
- Local login UI (`/login`, `/register`) returns a redirect to `/` when feature is enabled.

### Non-goals (YAGNI)
- JWT verification path (`X-authentik-jwt` + JWKS). The reference doc says it's the "higher assurance" alternative when the app can't be network-isolated; we rely on trusted-proxy CIDR. Easy to add later as a second mode.
- EE/SSO integration. Not in scope. EE code paths remain unchanged.
- Configurable prefix or configurable group→role mapping table. Hardcoded `analytics-` prefix per operator decision.
- Stripping of `X-authentik-meta-*` / `X-authentik-entitlements` (we only read the headers we care about; others are simply ignored, which is safe since `AuthentikProxy` is the only consumer of those names).
- Logout flow changes. `/logout` keeps working; after logout, next request hits Authentik proxy plug again and re-establishes a session (since the user is still authenticated upstream). This is the intended behavior with proxy auth.
- 2FA enforcement when Authentik is enabled (Authentik handles auth factors).
- API key / public API routes (they don't go through the `:browser` pipeline and are out of scope).
- Removing EE code; deferred.

---

## Findings (current auth mechanism)

### Stack
Elixir 1.19 / Phoenix 1.8 / Phoenix LiveView. Plausible Analytics fork at `analytics/`.

### Login flow (CE)
- Routes (lib/plausible_web/router.ex):
  - `GET /login` / `POST /login` → `PlausibleWeb.AuthController.login_form/2` and `:login/2`
  - `GET/POST /password/request-reset`, `/password/reset` → `AuthController.password_reset_*`
  - `GET/POST /2fa/*` → `AuthController.*_2fa*`
  - `GET /activate`, `POST /activate/*` → `AuthController.activate*`
  - `GET /logout` → `AuthController.logout/2`
  - `LIVE /register` → `PlausibleWeb.Live.RegisterForm` (creates `Auth.User` via `Auth.User.new/1` + `Repo.insert` + `Teams.get_or_create/1`).
- On successful login, `AuthController.login/2` calls `PlausibleWeb.UserAuth.log_in_user(conn, user, redirect_path)`.

### Session establishment
- `lib/plausible_web/user_auth.ex`:
  - `log_in_user(conn, %Auth.User{} = user, redirect_path)` (line 25):
    1. Creates a server-side `Auth.UserSession` row via `Plausible.Auth.UserSessions.create!(user, device_name)`.
    2. `renew_session/1`: deletes CSRF token, configures `Plug.Conn.configure_session(renew: true)`, then `clear_session/1`.
    3. Stores `:user_token => session.token` and `:live_socket_id` in the cookie session.
    4. Sets a separate `logged_in=true` cookie for the static site.
    5. Redirects to `login_redirect_path/2`.
  - `log_out_user(conn)`: removes server-side session by token, disconnects LiveView sockets, `renew_session/1`, clears `logged_in` cookie.

### Per-request auth pipeline
- `pipeline :browser` (router.ex line 6) chains:
  1. `:accepts ["html"]`
  2. `:fetch_session`
  3. `:fetch_live_flash`
  4. `:put_secure_browser_headers`
  5. `PlausibleWeb.Plugs.NoRobots`
  6. `PlausibleWeb.FirstLaunchPlug` (CE only — `on_ee` is falsy)
  7. `PlausibleWeb.AuthPlug` — reads `user_token` from session, populates `:current_user`, `:current_user_session`, `:my_team`, `:current_team`, `:current_team_role`, `:teams`.
  8. `PlausibleWeb.Plugs.UserSessionTouch`
  9. `:put_root_layout`
- `pipeline :api` and `:internal_stats_api` also use `AuthPlug` after `:fetch_session`.

### User schema (lib/plausible/auth/user.ex)
- `Plausible.Auth.User`, table `users`. Key fields: `email :string` (unique), `name :string`, `password_hash :string`, `email_verified :boolean`, `theme`, `last_team_identifier :uuid`, plus 2FA fields.
- `new/1` requires `[:email, :name, :password]`, validates password length+strength+confirmation, hashes, sets `email_verified` according to CE config flag. NOT suitable for JIT (validates real password) — we'll skip `User.new/1` and build a changeset manually for JIT.
- For JIT we'll build a changeset that casts `[:email, :name]`, sets `password_hash` to a randomly-generated unusable hash (mirroring `extra/lib/plausible/auth/sso.ex:454-457` pattern: `:crypto.strong_rand_bytes(64) |> Base.encode64` then `Plausible.Auth.Password.hash/1`), and `email_verified: true`.

### Roles / authorization
- `Plausible.Teams.Membership` (lib/plausible/teams/membership.ex), `@roles [:guest, :viewer, :editor, :admin, :owner, :billing]`.
- Roles are scoped to (user, team). For our purposes, role lives on the user's personal team's membership.
- `super_admin_user_ids` is a list of user IDs from `ADMIN_USER_IDS` env var (config/runtime.exs:94-102) — separate global-admin concept used by `SuperAdminOnlyPlug`. Not affected by group mapping; out of scope.

### SSO
- `extra/lib/plausible/auth/sso.ex` exists in EE only (excluded from CE compile via `mix.exs` `elixirc_paths`). The `provision_identity/3` function (line 453) is our reference for JIT (random password + `email_verified: true` + transactional create-and-link-membership). We will write a CE-local equivalent.
- `:simple_saml` dependency: used by EE SSO only.

### Logout
- `AuthController.logout/2` calls `UserAuth.log_out_user/1`, redirects to `params["redirect"] || "/"`.

### Session config (lib/plausible_web/endpoint.ex)
- Cookie-based `:plug_session_store`, key `_plausible_key` (CE), 5y max_age, `SameSite=Lax`, signing salt baked in source. CE does not modify the session opts at runtime aside from `secure` flag. Nothing to change here.

### Existing trusted-proxy handling
- `PlausibleWeb.RemoteIP.get/1` (lib/plausible_web/remote_ip.ex) extracts client IP from `x-plausible-ip`, `cf-connecting-ip`, `x-forwarded-for`, `b-forwarded-for`, `forwarded`, falling back to `conn.remote_ip`. **No notion of trusted proxy IPs** — it just trusts whatever comes in. This is used for analytics ingestion, not for auth. For our purposes:
  - We need `conn.remote_ip` (the raw TCP peer) to be the outpost. Plausible already binds to `LISTEN_IP=127.0.0.1` by default, and the outpost reverse-proxies through it. We'll use `conn.remote_ip` for the trust check, NOT any forwarded header.
- No existing `trusted_proxies` config key. We add `AUTHENTIK_PROXY_TRUSTED_IPS` (CIDR list).

### Tests for auth
- `test/plausible_web/plugs/auth_plug_test.exs` — our model.
- `test/plausible_web/controllers/auth_controller_test.exs` — login/logout coverage.
- `test/plausible_web/plugs/first_launch_plug_test.exs` — pattern for plugs that conditionally redirect.
- `test/support/` — `ConnCase` + factories.

### Config surface
- `config/runtime.exs` reads env vars via `Plausible.ConfigHelpers.get_var_from_path_or_env/3` and `get_bool_from_path_or_env/3` (supports both env vars and `${CONFIG_DIR}/<VAR>` file mounts à la docker secrets).
- We add three keys:
  - `AUTHENTIK_PROXY_ENABLED` (bool, default `false`)
  - `AUTHENTIK_PROXY_TRUSTED_IPS` (comma-separated CIDR list; required when enabled)
  - `AUTHENTIK_PROXY_GROUP_PREFIX` (default `analytics-`) — keeps the hardcoding swappable per operator deployment without code changes; lower-risk than truly hardcoding.

---

## Plan

### Files to add
1. `lib/plausible_web/plugs/authentik_proxy.ex` — the only new piece of logic.
2. `lib/plausible/auth/authentik.ex` — small support module: parse groups → role, JIT-provision user, sync membership role. Pure functions + DB ops; easy to test in isolation.
3. `test/plausible_web/plugs/authentik_proxy_test.exs` — plug behaviour tests (no role/JIT logic, just plug-level: trust IP, header stripping, redirect on disabled, halt on missing group, etc.).
4. `test/plausible/auth/authentik_test.exs` — role mapping, JIT provisioning, role sync tests.

### Files to modify
5. `config/runtime.exs` — add three env vars, expose them via `config :plausible, :authentik_proxy, [...]`.
6. `lib/plausible_web/router.ex` — insert `plug PlausibleWeb.Plugs.AuthentikProxy` in the `:browser` and `:api` pipelines (so LiveView mounts and JSON API consumers behind the proxy both work). Position: after `:fetch_session`, before `PlausibleWeb.AuthPlug`.
7. `lib/plausible_web/controllers/auth_controller.ex` — when `Authentik.enabled?/0`, the `login_form/2`, `password_reset_request_form/2`, `activate_form/2`, `verify_2fa_form/2` etc. handlers redirect to `/` (we'll add a single short-circuit guard at the top of the controller). Logout still works: it clears the local session; the next request re-establishes via the plug.
8. `lib/plausible_web/router.ex` — the live route `/register` is gated by `MaybeDisableRegistration` plug already; we also add a check or just rely on `AUTHENTIK_PROXY_ENABLED` making `DISABLE_REGISTRATION=true` operationally. Cleaner: when Authentik enabled, redirect `/register` to `/`. We'll put that redirect in a tiny new plug or piggyback on `MaybeDisableRegistration`.

### Plug logic (lib/plausible_web/plugs/authentik_proxy.ex)

```
init(opts) -> opts (no-op)

call(conn, _) ->
  if not enabled?():
    conn  # pass through; existing auth handles
  else:
    conn = strip_authentik_headers_unless_trusted(conn)
    case authentik_email(conn) do
      nil ->
        conn  # no headers (or stripped) -> existing AuthPlug will get anonymous; if a downstream route requires login the existing redirect to /login happens. But /login itself is now redirected to /, so this would loop. So instead: when enabled AND no headers AND request needs auth -> return 401 (or just let existing flow handle and rely on outpost to never let unauthenticated users through).
      email ->
        case Authentik.role_from_groups(groups_header) do
          {:error, :no_role} -> conn |> send_resp(403, "No access") |> halt()
          {:ok, role} ->
            case Authentik.provision_or_get(email, name) do
              {:ok, user} ->
                :ok = Authentik.sync_role(user, role)
                if already_logged_in_as?(conn, user) do
                  conn  # session already matches, no-op
                else
                  UserAuth.log_in_user_no_redirect(conn, user)  # see helper below
                end
              {:error, reason} -> log + 500
            end
        end
    end
```

Trust check (`strip_authentik_headers_unless_trusted/1`):
- Read `conn.remote_ip` (a `:inet.ip_address` tuple — IPv4 4-tuple or IPv6 8-tuple).
- For each configured CIDR, parse with `InetCidr` if available, else implement a small CIDR-match helper (no extra dep — bitwise compare against parsed address+mask).
- If `remote_ip` matches any trusted CIDR: keep headers. Otherwise: delete all `x-authentik-*` request headers from `conn.req_headers` and return.
- We use the raw TCP peer IP, not any forwarded header — the operator deployment is "outpost → app on localhost" or "outpost → app over private network", and `conn.remote_ip` is exactly that peer.

Helper needed in `PlausibleWeb.UserAuth`:
- Existing `log_in_user/3` finishes with `Phoenix.Controller.redirect(...)`. For the plug we need the same session setup but without halting — so the request continues to its actual route handler. Add `log_in_user_no_redirect/2` (new public function) that does steps 1–3 (create UserSession + set token + cookie) and returns the conn. Refactor existing `log_in_user/3` to call it then redirect, so we keep one implementation.

### Auth-side module (lib/plausible/auth/authentik.ex)

```elixir
defmodule Plausible.Auth.Authentik do
  alias Plausible.{Auth, Repo, Teams}
  alias Plausible.Teams.Membership

  @role_priority [:owner, :admin, :editor, :billing, :viewer]
  # billing intentionally below admin in our app-role precedence

  def enabled?(), do: Application.get_env(:plausible, :authentik_proxy)[:enabled] == true
  def trusted_cidrs(), do: Application.get_env(:plausible, :authentik_proxy)[:trusted_cidrs] || []
  def group_prefix(), do: Application.get_env(:plausible, :authentik_proxy)[:group_prefix] || "analytics-"

  @spec role_from_groups(String.t() | nil) :: {:ok, atom()} | {:error, :no_role}
  def role_from_groups(nil), do: {:error, :no_role}
  def role_from_groups(groups_str) do
    prefix = group_prefix()
    candidates =
      groups_str
      |> String.split("|", trim: true)
      |> Enum.flat_map(fn g ->
        case String.split(g, prefix, parts: 2) do
          ["", rest] -> [String.to_existing_atom(rest)]  # safe because @role_priority pre-creates atoms
          _ -> []
        end
      end)
      |> MapSet.new()

    case Enum.find(@role_priority, &MapSet.member?(candidates, &1)) do
      nil -> {:error, :no_role}
      role -> {:ok, role}
    end
  end

  @spec provision_or_get(email :: String.t(), name :: String.t() | nil) ::
          {:ok, Auth.User.t()} | {:error, Ecto.Changeset.t()}
  def provision_or_get(email, name) do
    case Repo.get_by(Auth.User, email: email) do
      %Auth.User{} = u -> {:ok, u}
      nil -> create_jit_user(email, name)
    end
  end

  defp create_jit_user(email, name) do
    Repo.transaction(fn ->
      random_password = :crypto.strong_rand_bytes(64) |> Base.encode64(padding: false)
      changeset =
        %Auth.User{}
        |> Ecto.Changeset.cast(%{email: email, name: name || email}, [:email, :name])
        |> Ecto.Changeset.validate_required([:email, :name])
        |> Ecto.Changeset.put_change(:password_hash, Auth.Password.hash(random_password))
        |> Ecto.Changeset.put_change(:email_verified, true)
        |> Ecto.Changeset.unique_constraint(:email)

      case Repo.insert(changeset) do
        {:ok, user} ->
          {:ok, _team} = Teams.get_or_create(user)
          user
        {:error, %Ecto.Changeset{errors: [email: {_, [{:constraint, :unique} | _]}]}} ->
          # race: another request created this user concurrently. Refetch.
          Repo.get_by!(Auth.User, email: email)
        {:error, cs} -> Repo.rollback(cs)
      end
    end)
    |> case do
      {:ok, user} -> {:ok, user}
      {:error, cs} -> {:error, cs}
    end
  end

  @spec sync_role(Auth.User.t(), atom()) :: :ok
  def sync_role(user, target_role) do
    {:ok, team} = Teams.get_or_create(user)
    case Repo.get_by(Membership, user_id: user.id, team_id: team.id) do
      nil ->
        # get_or_create should have created the owner membership; if missing, create at target_role
        %Membership{}
        |> Ecto.Changeset.change(%{role: target_role, user_id: user.id, team_id: team.id})
        |> Repo.insert!()
      %Membership{role: ^target_role} -> :ok
      %Membership{role: :owner} ->
        # Personal-team owner. Don't downgrade the owner of a personal team based on group changes,
        # because that would orphan the team. Owner stays owner regardless of Authentik group.
        :ok
      %Membership{} = m ->
        m |> Ecto.Changeset.change(%{role: target_role}) |> Repo.update!()
    end
    :ok
  end
end
```

### Pipeline order in router.ex (`:browser`)
```
:accepts ["html"]
:fetch_session
:fetch_live_flash
:put_secure_browser_headers
PlausibleWeb.Plugs.NoRobots
PlausibleWeb.FirstLaunchPlug, redirect_to: "/register"  (existing, on_ce only)
PlausibleWeb.Plugs.AuthentikProxy                       ## NEW — before AuthPlug
PlausibleWeb.AuthPlug
PlausibleWeb.Plugs.UserSessionTouch
:put_root_layout, html: {PlausibleWeb.LayoutView, :app}
```

For `:api` pipeline: same — insert `AuthentikProxy` after `:fetch_session`, before `AuthPlug`.

### Auth controller skip
Add a `plug :skip_local_auth_ui_when_authentik` private plug at the top of `PlausibleWeb.AuthController`, applied to login/password/2FA/activate actions. When `Authentik.enabled?()` is true, it sends a redirect to `/` and halts.

For `RegisterForm` LiveView: redirect on mount when enabled. Single line in `mount/3`.

### CIDR matching
- Avoid adding a new dependency. Write a 20-line helper in `Plausible.Auth.Authentik`:
  ```
  parse_cidr("10.0.0.0/8") -> {ip_tuple, prefix_len}
  in_cidr?(remote_ip_tuple, {cidr_ip, prefix_len}) ->
    same address family + (ip_to_int(remote) >>> (bits - prefix)) == (ip_to_int(cidr) >>> (bits - prefix))
  ```
- IPv4 (32 bits) and IPv6 (128 bits) both handled.
- Parse CIDR list once at app start (in `runtime.exs`) and store the parsed tuples in app env so the plug doesn't reparse per request.

### Config in runtime.exs (added)
```elixir
authentik_proxy_enabled =
  get_bool_from_path_or_env(config_dir, "AUTHENTIK_PROXY_ENABLED", false)

authentik_proxy_trusted_cidrs =
  config_dir
  |> get_var_from_path_or_env("AUTHENTIK_PROXY_TRUSTED_IPS", "")
  |> String.split(",", trim: true)
  |> Enum.map(&String.trim/1)
  |> Enum.map(&Plausible.Auth.Authentik.parse_cidr!/1)  # raises on bad input -> hard fail

if authentik_proxy_enabled and authentik_proxy_trusted_cidrs == [] do
  raise "AUTHENTIK_PROXY_ENABLED is true but AUTHENTIK_PROXY_TRUSTED_IPS is empty. Refusing to start: would trust unauthenticated headers from any source."
end

authentik_proxy_prefix =
  get_var_from_path_or_env(config_dir, "AUTHENTIK_PROXY_GROUP_PREFIX", "analytics-")

config :plausible, :authentik_proxy,
  enabled: authentik_proxy_enabled,
  trusted_cidrs: authentik_proxy_trusted_cidrs,
  group_prefix: authentik_proxy_prefix
```

### Assumptions (explicit)
- Plausible CE deployment binds the HTTP listener to localhost or a private network behind the Authentik outpost. `conn.remote_ip` reflects the outpost's peer IP. This is consistent with the reference doc's "bind app to localhost/private network" guidance.
- The personal team auto-created by `Teams.get_or_create/1` makes the user the `:owner`. We do NOT downgrade owners on subsequent requests even if their Authentik group changes — that role lock prevents the personal team from becoming ownerless. `analytics-admin` on a user who is owner of their personal team is effectively a no-op for that team's membership row but stored elsewhere if needed (not implemented; YAGNI).
- We trust the Authentik outpost to strip any inbound spoofed `X-authentik-*` headers from the public internet. As defense-in-depth we **also** strip them in our own plug when `conn.remote_ip` is not in the trusted CIDR set.
- Users authenticated via Authentik have `email_verified: true` because Authentik already verified them.
- Logout: clearing the local session does not log out of Authentik. The next request re-creates the session via the proxy plug. This is acceptable and matches how proxy-auth setups normally behave; users wanting to fully sign out go through Authentik's logout. Logout still removes the local DB session row (revoking LiveView sockets).
- The `:role` atoms `:owner`, `:admin`, `:editor`, `:viewer`, `:billing` are pre-existing as atoms (defined in `Plausible.Teams.Membership.@roles`), so `String.to_existing_atom/1` is safe.
- Plausible already loads `extra/lib/` in non-CE compilation; my plug lives in `lib/` only and references no EE modules.

---

## Debate Notes

Reviewer: claude-debater. Verified against source: `router.ex`, `endpoint.ex`, `user_auth.ex`, `auth_plug.ex`, `auth_controller.ex`, `teams.ex` (`get_or_create` + `create_my_team`), `teams/membership.ex`, `require_logged_out.ex`. Settled decisions from operator were not re-debated.

### Verdict

REVISE: fix issues 1, 2, 3, 4, 6, 7, 8 before shipping. The overall shape (trusted-CIDR plug + small JIT module + auth-controller short-circuit) is correct, but several concrete details are wrong as written and will cause incorrect behaviour, 500s, or test gaps.

### Problems in Current Plan

1. **[HIGH] Session-collision logic for identity change is not in the plan.** The plug pseudocode says "if already_logged_in_as?(conn, user) then conn else log_in_user_no_redirect". But there is no path for "logged in as A, Authentik says B". With the proposed code, the plug would call `log_in_user_no_redirect` and the new helper would `renew_session` + `clear_session` + `put_session(:user_token, B_token)`, so it works *if* the helper is correctly written. The risk is that the helper is currently described as "do steps 1-3" of `log_in_user/3` — i.e. it WILL renew, since `set_user_token/2` calls `renew_session/1` (verified in `user_auth.ex:131-136`). But the *old server-side `UserSession` row for A* is left dangling and the old `live_socket_id` for A is not disconnected. Result: A's open LiveView tabs in another window keep streaming as A even after this browser switches to B. Fix: when switching identities, call `UserAuth.log_out_user/1` first (which removes the DB session row and disconnects sockets), then `log_in_user_no_redirect`. The "already-logged-in-as-the-same-user" fast path must compare `current_user_session.user_id` (not just `current_user`) so re-rotation is avoided per request.

2. **[HIGH] JIT race-condition match is fragile and partly wrong.** The proposed match `{:error, %Ecto.Changeset{errors: [email: {_, [{:constraint, :unique} | _]}]}}` assumes the email error is the only error and the constraint tuple is first in the keyword. In Ecto 3.13 `errors` is a keyword list and may include multiple entries; constraint detection should be done by inspecting the value's keyword like the EE SSO module does (`extra/lib/plausible/auth/sso.ex:493`: `true = {:constraint, :unique} in attrs`). Even more importantly, **`Repo.transaction` wrapped around an insert that returns `{:error, cs}` and then `Repo.get_by!` will deadlock-prone is fine, but if the insert fails with a non-unique error the current `Repo.rollback(cs)` returns `{:error, cs}` — which the outer `case` *does* handle. However, the bigger bug: `Teams.get_or_create(user)` is called *inside* the transaction; it itself opens internal repo operations and is not designed to be wrapped in an outer transaction (it does `insert!` + conditional `delete!` based on conflict). Wrapping it in `Repo.transaction` is unnecessary and increases lock surface. Fix: drop the outer `Repo.transaction`; do `Repo.insert(changeset)` directly, on `{:error, cs}` use a robust helper `unique_email_violation?(cs)` (mirroring SSO module) then refetch; on success call `Teams.get_or_create(user)` outside the transaction. Also, `Auth.Password.hash/1` — verify this exact function exists; the existing JIT reference in `extra/lib/plausible/auth/sso.ex:454-457` is the source of truth. (Confirmed at `lib/plausible/auth/password.ex` per repo conventions; planner must double-check the public function name and arity before coding.)

3. **[MED] Header stripping placement leaves a small window.** Stripping inside the `:browser` pipeline plug means earlier plugs (`:fetch_session`, `:put_secure_browser_headers`, `NoRobots`, `FirstLaunchPlug`) see the raw headers. Verified none of those read `x-authentik-*`. So functionally safe today. BUT: the `:api` pipeline does not include `NoRobots`/`FirstLaunchPlug`, so the stripping plug must also run in `:api` (plan already says so — good). Stronger fix recommended for defence-in-depth: do the strip in `endpoint.ex` as a tiny `:strip_authentik_if_untrusted` plug installed *before* `Plug.RequestId` and `Sentry.PlugContext`, so even Sentry context never captures spoofed headers. This is cheap (one extra plug call per request), survives router refactors, and is "set once and forget". The trust check + identity application still belongs in a router plug. Recommend: split into two plugs (a) endpoint-level strip-on-untrusted, (b) router-level identity-and-session.

4. **[MED] No CIDR matching for IPv6-mapped IPv4.** Cowboy on dual-stack listeners can deliver IPv4 peers as IPv6-mapped (`::ffff:127.0.0.1`, i.e. `{0,0,0,0,0,0xffff,0x7f00,0x0001}`). If the operator configures `127.0.0.0/8` (IPv4) but the listener delivers v6-mapped, the trust check fails closed and the app silently treats every request as anonymous → 403 storm. Fix: in `in_cidr?/2`, normalise v6-mapped-v4 (`{0,0,0,0,0,0xffff,a,b}`) to its v4 form before family-comparison, OR document loudly that operators must configure both forms, OR auto-expand v4 CIDRs to v6-mapped equivalents.

5. **[LOW] `Plug.RequestId` ordering is fine.** Verified `Plug.RequestId` is in `endpoint.ex` line 71 and runs before router; it doesn't read `x-authentik-*`. No issue.

6. **[MED] Auth-controller short-circuit collides with `RequireLoggedOutPlug`.** Verified: `auth_controller.ex:14-26` already installs `RequireLoggedOutPlug when action in [...]` for `login_form`, `login`, `register`, `verify_2fa_*`. Behaviour with Authentik enabled: our plug establishes a session before AuthController runs, so `conn.assigns[:current_user]` is set → `RequireLoggedOutPlug` redirects to `/sites`. That means **the proposed "redirect to /" short-circuit is unnecessary for those actions** — they already redirect to `/sites`. The proposed plug is only needed for actions NOT in that list: `password_reset_request_form`, `password_reset_form`, `password_reset`, `activate_form`, `activate`, `request_activation_code`, and the various 2FA-setup actions. Recommend: rename the plug to `:skip_self_service_actions_when_authentik` and apply it only to the password-reset / activate / 2FA-setup action set. Cleaner, smaller diff, no double-redirect ambiguity. For the LiveView `/register` route: it's gated by `RequireLoggedOutPlug` in the router pipeline (line 436), and our plug establishes session before the pipeline, so the user is logged-in → redirected to `/sites`. **No code change needed for `/register`.** Drop the proposed redirect-on-mount.

7. **[MED] Sync-role semantics for "user with personal team + an `analytics-viewer` group" is surprising but acceptable; document it.** The role-lock for owners of personal teams is the right safety call (alternative — auto-deleting the team — is way worse). Acceptable as-is, but the plan must add explicit log line (`Logger.info`) when a downgrade is suppressed, and the test suite must assert it (see issue 8). Also: the `Membership` changeset uses `put_assoc` (verified `teams/membership.ex:30-36`), not raw `user_id`/`team_id` change. The proposed `Ecto.Changeset.change(%{role: target_role, user_id: ..., team_id: ...})` won't set the belongs_to assocs through `change/2` cleanly — use `Teams.Membership.changeset(team, user, role)` instead. (And note: if `Teams.get_or_create/1` returned `:ok` the owner membership IS always created via `create_my_team`, so the "nil membership" branch in `sync_role` is dead code under happy path; keep it as a defensive insert-if-missing but mark it as such.)

8. **[MED] Test plan is missing several critical cases.** The proposed test files cover the happy paths but miss:
   - (a) identity-switch invalidation: logged in as A, request arrives with Authentik headers for B → old `Auth.UserSession` row for A is deleted, new row for B exists, response `current_user` is B.
   - (b) trusted-IP IPv6 case: peer is `{0,0,0,0,0,0,0,1}` (`::1`) and CIDR `::1/128` matches.
   - (c) trusted-IP IPv6-mapped IPv4 case (per issue 4).
   - (d) header strip on `:api` pipeline (not just `:browser`).
   - (e) JIT race: simulate concurrent insert by inserting the user via factory, then call `provision_or_get/2` and assert it returns the pre-existing user (no crash).
   - (f) role-lock log emission for personal-team owner.
   - (g) `AUTHENTIK_PROXY_ENABLED=true` + empty CIDR list at boot → runtime.exs raises (configuration safety).
   - (h) `String.to_existing_atom` safety: if a group is `analytics-superuser` (not a known role), it must be silently ignored, NOT crash. **The current code uses `String.to_existing_atom/1` which WILL raise `ArgumentError` for unknown role strings if no other Erlang term has created that atom.** Fix: wrap in `try` or use a hardcoded map `%{"viewer" => :viewer, "editor" => :editor, "admin" => :admin, "owner" => :owner, "billing" => :billing}` and `Map.get/2`. This is safer and removes the implicit dependency on `@role_priority` atoms being preloaded.

9. **[LOW] LiveView `connect_info` session: no subtlety.** Verified `endpoint.ex:22-32`: LiveView socket reads session via `runtime_session_opts/0`, same cookie/key as HTTP. As long as the HTTP request that triggered the LV mount has the session cookie set by our plug before the response is sent to the browser, the subsequent WebSocket upgrade carries the cookie and LV reads the same `:user_token`. Confirmed safe. One micro-edge: if a request comes in *as* a WebSocket upgrade directly (no prior HTTP request established session), the Authentik headers on the WS upgrade request are not handled by our plug because router plugs don't run on socket upgrades. This is fine: the outpost requires HTTP auth on the initial page load, so by the time the WS upgrade happens the cookie session is already there. Document this assumption.

10. **[LOW] `runtime.exs` calls `Plausible.Auth.Authentik.parse_cidr!/1` at boot.** That works, but `runtime.exs` runs before application start, so the module must be compiled in. It will be (it's in `lib/`), but the planner should not call functions from `Plausible.Auth.Authentik` inside `runtime.exs` to avoid coupling boot config to a domain module — keep CIDR parsing as a private helper in `runtime.exs` or in a tiny `Plausible.ConfigHelpers` addition. Cleaner separation.

### Better Plan (deltas only)

- **Helper `log_in_user_no_redirect/2`**: extract from existing `log_in_user/3` (verified at `user_auth.ex:25-34`) — already a clean refactor target. Make the existing function call the new one then redirect. Three-line change.
- **AuthentikProxy plug logic** (revised):
  ```
  call(conn, _):
    if not enabled?(): conn
    else:
      conn = strip_if_untrusted(conn)         # always, even when no headers
      case email_header(conn) do
        nil -> conn                            # outpost will not let this happen; AuthPlug stays anonymous
        email ->
          case role_from_groups(groups_header(conn)) do
            :error -> conn |> send_resp(403, "Forbidden: no analytics-* group") |> halt()
            {:ok, role} ->
              {:ok, user} = Authentik.provision_or_get(email, name_header(conn))
              :ok = Authentik.sync_role(user, role)
              current_user_id = get_session_user_id(conn)
              cond do
                current_user_id == user.id -> conn          # fast path, no rotation
                is_nil(current_user_id)    -> log_in_user_no_redirect(conn, user)
                true ->                                      # identity change
                  conn |> UserAuth.log_out_user() |> log_in_user_no_redirect(user)
              end
          end
      end
  ```
- **Stripping**: install endpoint-level `:strip_authentik_if_untrusted` before `Plug.RequestId`. Router plug calls a no-op fallback (idempotent).
- **JIT** (revised):
  ```
  provision_or_get(email, name):
    case Repo.get_by(User, email: email) do
      %User{} = u -> {:ok, u}
      nil ->
        case Repo.insert(jit_changeset(email, name)) do
          {:ok, user} ->
            {:ok, _team} = Teams.get_or_create(user)
            {:ok, user}
          {:error, cs} ->
            if unique_email_violation?(cs) do
              {:ok, Repo.get_by!(User, email: email)}        # lost the race; partner request already created team
            else
              {:error, cs}
            end
        end
    end
  ```
  No outer `Repo.transaction`. `unique_email_violation?/1` mirrors `extra/lib/plausible/auth/sso.ex:493`.
- **Role mapping**: replace `String.to_existing_atom` with `Map.get(@group_to_role, suffix)`:
  ```
  @group_to_role %{"viewer" => :viewer, "editor" => :editor, "admin" => :admin, "billing" => :billing, "owner" => :owner}
  ```
  Iterate groups, collect matches, pick highest by `@role_priority`. Unknown suffixes silently skipped.
- **Sync role**: use `Teams.Membership.changeset(team, user, role)` for inserts; for updates, `Ecto.Changeset.change(membership, role: target_role) |> Repo.update!()`. Log when downgrade-of-owner is suppressed: `Logger.info("authentik: skipping role downgrade for personal-team owner #{user.id}")`.
- **AuthController short-circuit**: only apply the redirect plug to `[:password_reset_request_form, :password_reset_request, :password_reset_form, :password_reset, :activate_form, :activate, :request_activation_code, :force_initiate_2fa_setup, :initiate_2fa_setup, :verify_2fa_setup_form, :verify_2fa_setup, :disable_2fa, :generate_2fa_recovery_codes]`. `RequireLoggedOutPlug` handles the rest. No `RegisterForm` LiveView change needed.
- **CIDR helper**: normalise `{0,0,0,0,0,0xffff,a,b}` to `{a >>> 8, a &&& 0xff, b >>> 8, b &&& 0xff}` before v4 CIDR check.
- **Tests**: add the eight cases enumerated in issue 8.

### Recommendation

Planner: apply the deltas above (especially issues 1, 2, 6, 8 — they prevent real bugs and dead code). The overall architecture (single router plug + tiny auth module + auth-controller skip) is right; do not redesign. Once revisions are folded in, hand off to claude-implementor.

---

## Plan v2 (debate deltas folded in)

Architecture is unchanged. Concrete revisions to the v1 plan:

### Files (final list)

Add:
1. `lib/plausible_web/plugs/strip_authentik_headers.ex` — endpoint-level defence-in-depth strip. Installed in `endpoint.ex` before `Plug.RequestId`. Removes all `x-authentik-*` request headers when `conn.remote_ip` is not in any configured trusted CIDR. Always runs (cheap; CIDR list empty when feature disabled means it short-circuits to no-op).
2. `lib/plausible_web/plugs/authentik_proxy.ex` — router-level plug that reads headers, JIT-provisions, syncs role, establishes/switches/keeps session. Runs only when feature enabled.
3. `lib/plausible/auth/authentik.ex` — pure logic + DB ops: role mapping, JIT provisioning, role sync, CIDR helpers (`parse_cidr!/1`, `in_any_cidr?/2` including v6-mapped-v4 normalisation).
4. `test/plausible_web/plugs/strip_authentik_headers_test.exs`
5. `test/plausible_web/plugs/authentik_proxy_test.exs`
6. `test/plausible/auth/authentik_test.exs`

Modify:
7. `lib/plausible_web/user_auth.ex` — extract `log_in_user_no_redirect/2` from existing `log_in_user/3`; `log_in_user/3` calls the new helper then redirects. Public function. No behaviour change for existing callers.
8. `config/runtime.exs` — add three env vars: `AUTHENTIK_PROXY_ENABLED`, `AUTHENTIK_PROXY_TRUSTED_IPS`, `AUTHENTIK_PROXY_GROUP_PREFIX`. Parse CIDRs at boot using `Plausible.Auth.Authentik.parse_cidr!/1` (it's in `lib/` so it's compiled by the time runtime.exs runs — verified by existing pattern: runtime.exs already calls into compiled modules like `Plausible.Ingestion.Persistor.*`). Fail-fast when enabled with empty CIDR list. Expose under `config :plausible, :authentik_proxy, ...`.
9. `lib/plausible_web/endpoint.ex` — add `plug PlausibleWeb.Plugs.StripAuthentikHeaders` before `plug(Plug.RequestId)`.
10. `lib/plausible_web/router.ex` — insert `plug PlausibleWeb.Plugs.AuthentikProxy` in `:browser` pipeline after `PlausibleWeb.FirstLaunchPlug` (on_ce) and before `PlausibleWeb.AuthPlug`. Insert same plug in `:api` pipeline after `:fetch_session` and before `PlausibleWeb.AuthPlug`. Skip `:internal_stats_api`, `:docs_stats_api` (these are SPA/JSON consumers carrying a cookie; the cookie was set by `:browser` plug; the role check has already passed when the cookie was minted — no double-evaluation needed and avoids issues with API clients).
11. `lib/plausible_web/controllers/auth_controller.ex` — add private plug `:skip_self_service_when_authentik_enabled` applied to the self-service actions NOT covered by `RequireLoggedOutPlug` (list in §"Auth controller skip" below). When `Authentik.enabled?()`, plug halts with redirect to `/`. Do nothing for the action list covered by `RequireLoggedOutPlug`. No change to `RegisterForm` LV — `RequireLoggedOutPlug` on the router's `/register` pipeline (router.ex:436) already handles it.

### Endpoint-level strip plug

```elixir
defmodule PlausibleWeb.Plugs.StripAuthentikHeaders do
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
      Enum.reject(conn.req_headers, fn {k, _} -> String.starts_with?(k, "x-authentik-") end)
    %{conn | req_headers: cleaned}
  end
end
```

`Authentik.trusted_request?/1` returns `true` when feature is enabled AND `conn.remote_ip` matches one of the configured trusted CIDRs; returns `false` otherwise (including when feature is disabled — in disabled mode there is nothing to trust, so we still strip just in case). When the feature is disabled the strip is harmless — no consumer reads those headers.

### Authentik module (final shape)

```elixir
defmodule Plausible.Auth.Authentik do
  require Logger
  alias Plausible.{Auth, Repo, Teams}
  alias Plausible.Teams.Membership

  # Map header suffix (after stripping `analytics-` prefix) -> Plausible role atom.
  @group_to_role %{
    "viewer" => :viewer,
    "editor" => :editor,
    "admin"  => :admin,
    "billing" => :billing,
    "owner" => :owner
  }
  # Highest privilege first. Picked over the user's matched-role set.
  @role_priority [:owner, :admin, :editor, :billing, :viewer]

  # --- config accessors ---
  def config, do: Application.get_env(:plausible, :authentik_proxy, [])
  def enabled?, do: Keyword.get(config(), :enabled, false)
  def trusted_cidrs, do: Keyword.get(config(), :trusted_cidrs, [])
  def group_prefix, do: Keyword.get(config(), :group_prefix, "analytics-")

  # --- trust check ---
  def trusted_request?(%Plug.Conn{} = conn) do
    enabled?() and in_any_cidr?(conn.remote_ip, trusted_cidrs())
  end

  # --- role mapping ---
  def role_from_groups(nil), do: :error
  def role_from_groups(""),  do: :error
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

  # --- JIT provisioning ---
  def provision_or_get(email, name) when is_binary(email) do
    case Repo.get_by(Auth.User, email: email) do
      %Auth.User{} = u -> {:ok, u}
      nil ->
        case Repo.insert(jit_changeset(email, name)) do
          {:ok, user} ->
            {:ok, _team} = Teams.get_or_create(user)
            {:ok, user}
          {:error, cs} ->
            if unique_email_violation?(cs) do
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

  # --- role sync ---
  def sync_role(%Auth.User{} = user, target_role) when is_atom(target_role) do
    {:ok, team} = Teams.get_or_create(user)
    case Repo.get_by(Membership, user_id: user.id, team_id: team.id) do
      nil ->
        Membership.changeset(team, user, target_role) |> Repo.insert!()
      %Membership{role: ^target_role} -> :ok
      %Membership{role: :owner} ->
        Logger.info("authentik: not changing role of personal-team owner (user_id=#{user.id})")
        :ok
      %Membership{} = m ->
        m |> Ecto.Changeset.change(role: target_role) |> Repo.update!()
    end
    :ok
  end

  # --- CIDR ---
  @spec parse_cidr!(String.t()) :: {:inet.ip_address(), non_neg_integer()}
  def parse_cidr!(str) when is_binary(str) do
    [ip_str, prefix_str] = String.split(str, "/", parts: 2)
    {:ok, ip} = :inet.parse_address(String.to_charlist(ip_str))
    {prefix, ""} = Integer.parse(prefix_str)
    max = if tuple_size(ip) == 4, do: 32, else: 128
    unless prefix in 0..max do
      raise "Invalid CIDR prefix #{prefix} in #{str}"
    end
    {ip, prefix}
  end

  def in_any_cidr?(_ip, []), do: false
  def in_any_cidr?(ip, cidrs), do: Enum.any?(cidrs, &in_cidr?(ip, &1))

  defp in_cidr?(ip, {cidr_ip, prefix}) do
    ip = normalise_v4mapped(ip)
    cidr_ip = normalise_v4mapped(cidr_ip)
    cond do
      tuple_size(ip) != tuple_size(cidr_ip) -> false
      tuple_size(ip) == 4 -> bit_match(ip_to_int(ip, 32), ip_to_int(cidr_ip, 32), 32 - prefix)
      true               -> bit_match(ip_to_int(ip, 128), ip_to_int(cidr_ip, 128), 128 - prefix)
    end
  end

  defp normalise_v4mapped({0,0,0,0,0,0xffff,a,b}), do: {div(a, 256), rem(a, 256), div(b, 256), rem(b, 256)}
  defp normalise_v4mapped(ip), do: ip

  defp ip_to_int({a,b,c,d}, 32), do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d
  defp ip_to_int({a,b,c,d,e,f,g,h}, 128) do
    (a <<< 112) + (b <<< 96) + (c <<< 80) + (d <<< 64) + (e <<< 48) + (f <<< 32) + (g <<< 16) + h
  end
  defp bit_match(_, _, shift) when shift < 0, do: false
  defp bit_match(x, y, shift), do: (x >>> shift) == (y >>> shift)
end
```

Note: `import Bitwise` is required at the top.

### AuthentikProxy plug (final shape)

```elixir
defmodule PlausibleWeb.Plugs.AuthentikProxy do
  @behaviour Plug
  import Plug.Conn
  alias Plausible.Auth.Authentik
  alias PlausibleWeb.UserAuth

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    cond do
      not Authentik.enabled?() -> conn
      not Authentik.trusted_request?(conn) -> conn  # headers were already stripped by endpoint plug; nothing to do
      true -> apply_identity(conn)
    end
  end

  defp apply_identity(conn) do
    email = header(conn, "x-authentik-email") |> normalise_email()
    name  = header(conn, "x-authentik-name")
    groups = header(conn, "x-authentik-groups")

    cond do
      is_nil(email) ->
        # Trusted source said nothing about a user. Pass through as anonymous.
        conn

      true ->
        case Authentik.role_from_groups(groups) do
          :error ->
            conn |> send_resp(403, "Forbidden: missing required group") |> halt()
          {:ok, role} ->
            with {:ok, user} <- Authentik.provision_or_get(email, name),
                 :ok        <- Authentik.sync_role(user, role) do
              maybe_switch_session(conn, user)
            else
              {:error, _cs} ->
                conn |> send_resp(500, "Authentication backend error") |> halt()
            end
        end
    end
  end

  defp maybe_switch_session(conn, user) do
    current_id = current_user_id_from_session(conn)
    cond do
      current_id == user.id -> conn
      is_nil(current_id) -> UserAuth.log_in_user_no_redirect(conn, user)
      true ->
        conn
        |> UserAuth.log_out_user()      # removes old DB session, disconnects LV sockets, renews session
        |> UserAuth.log_in_user_no_redirect(user)
    end
  end

  defp current_user_id_from_session(conn) do
    case UserAuth.get_user_session(conn) do
      {:ok, session} -> session.user_id
      _ -> nil
    end
  end

  defp header(conn, name), do: get_req_header(conn, name) |> List.first()
  defp normalise_email(nil), do: nil
  defp normalise_email(s), do: s |> String.trim() |> String.downcase() |> then(&if &1 == "", do: nil, else: &1)
end
```

### `UserAuth` refactor

```elixir
def log_in_user(conn, %Auth.User{} = user, redirect_path) do
  redirect_to = login_redirect_path(conn, redirect_path)
  conn
  |> log_in_user_no_redirect(user)
  |> Phoenix.Controller.redirect(to: redirect_to)
end

@spec log_in_user_no_redirect(Plug.Conn.t(), Auth.User.t()) :: Plug.Conn.t()
def log_in_user_no_redirect(conn, %Auth.User{} = user) do
  device_name = get_device_name(conn)
  session = Auth.UserSessions.create!(user, device_name)
  conn
  |> set_user_token(session.token)
  |> set_logged_in_cookie()
end
```

Existing EE branch of `log_in_user/3` (`Auth.SSO.Identity` case) is untouched — it's gated by `on_ee` and only compiled in EE builds; we don't change it.

### Auth controller skip plug (final action list)

```elixir
plug :skip_self_service_when_authentik when action in [
  :activate_form,
  :activate,
  :request_activation_code,
  :password_reset_request_form,
  :password_reset_request,
  :password_reset_form,
  :password_reset,
  :force_initiate_2fa_setup,
  :initiate_2fa_setup,
  :verify_2fa_setup_form,
  :verify_2fa_setup,
  :disable_2fa,
  :generate_2fa_recovery_codes
]

defp skip_self_service_when_authentik(conn, _opts) do
  if Plausible.Auth.Authentik.enabled?() do
    conn |> Phoenix.Controller.redirect(to: "/") |> halt()
  else
    conn
  end
end
```

Login/register/verify-2FA are NOT in this list because `RequireLoggedOutPlug` already redirects logged-in users to `/sites`, and under Authentik mode the user is always logged in before reaching the controller.

### Config in runtime.exs

```elixir
authentik_proxy_enabled =
  get_bool_from_path_or_env(config_dir, "AUTHENTIK_PROXY_ENABLED", false)

authentik_proxy_trusted_cidrs =
  config_dir
  |> get_var_from_path_or_env("AUTHENTIK_PROXY_TRUSTED_IPS", "")
  |> String.split(",", trim: true)
  |> Enum.map(&String.trim/1)
  |> Enum.reject(&(&1 == ""))
  |> Enum.map(&Plausible.Auth.Authentik.parse_cidr!/1)

if authentik_proxy_enabled and authentik_proxy_trusted_cidrs == [] do
  raise """
  AUTHENTIK_PROXY_ENABLED=true but AUTHENTIK_PROXY_TRUSTED_IPS is empty.
  Refusing to start: would either trust every source or trust none. Configure CIDRs of the Authentik outpost.
  """
end

config :plausible, :authentik_proxy,
  enabled: authentik_proxy_enabled,
  trusted_cidrs: authentik_proxy_trusted_cidrs,
  group_prefix: get_var_from_path_or_env(config_dir, "AUTHENTIK_PROXY_GROUP_PREFIX", "analytics-")
```

The debater flagged this couples runtime.exs to a domain module. Plausible's runtime.exs already calls into domain modules (e.g. `Plausible.Ingestion.Persistor.*` in lines 148-153), so the convention is fine here; we accept this trade-off in exchange for not duplicating CIDR parsing in `ConfigHelpers`.

### Assumptions (final, additive)
- `Plausible.Auth.Authentik` module is compiled before `runtime.exs` runs because runtime.exs runs at app boot after compilation (verified pattern in runtime.exs line 152). Calling `Authentik.parse_cidr!/1` from runtime.exs is safe.
- WebSocket upgrades for LiveView always follow at least one HTTP request that went through the router plugs, so the session cookie is set before the upgrade. We do not run AuthentikProxy on the WS upgrade path (router plugs do not execute there).
- A user with `analytics-owner` group whose personal-team membership is already `:owner` is a no-op (matches `^target_role` branch). A user with `analytics-viewer` group whose personal-team membership is `:owner` triggers the "owner role lock" branch (no change + log line). This is intentional and documented.
- Logout button still works (clears local session row + sockets). The next user action triggers Authentik proxy plug, which re-establishes a fresh session for the same user. This is the standard proxy-auth UX.
- IPv6-mapped IPv4 addresses (`::ffff:a.b.c.d`) are normalised to their IPv4 form before CIDR matching, so operators only need to configure IPv4 CIDRs for `127.0.0.0/8` style setups.

---

## Task Briefs

### Task 1 — Add `Plausible.Auth.Authentik` module

**Context.** New CE-only module. Lives at `lib/plausible/auth/authentik.ex`. Pure functions + DB ops; no Plug. Used by the strip plug, the router plug, and `config/runtime.exs`. Plausible Auth conventions: see `lib/plausible/auth/user.ex` for changeset style, `lib/plausible/teams.ex` for team accessor patterns.

**Objective.** Provide: (a) feature config accessors (`enabled?/0`, `trusted_cidrs/0`, `group_prefix/0`, `trusted_request?/1`); (b) `role_from_groups/1` returning `{:ok, role_atom}` or `:error`; (c) `provision_or_get/2` performing race-safe JIT user creation + personal-team creation; (d) `sync_role/2` upserting the personal-team membership at the target role with owner-lock semantics; (e) CIDR helpers `parse_cidr!/1`, `in_any_cidr?/2` with v6-mapped-v4 normalisation.

**Scope.**
- Create `lib/plausible/auth/authentik.ex` implementing exactly the module shown in "Plan v2 → Authentik module (final shape)" above. Include `require Logger` and `import Bitwise`.
- Use `Plausible.Auth.Password.hash/1` (defined at `lib/plausible/auth/password.ex:2`) for the random password.
- Use `Plausible.Teams.get_or_create/1` (defined at `lib/plausible/teams.ex:151`) to create/fetch the personal team.
- Use `Plausible.Teams.Membership.changeset/3` for new memberships and a `Ecto.Changeset.change/2` for role updates (see existing usage patterns).
- Do NOT depend on or reference anything in `extra/lib/`.

**Non-goals / Later.**
- Do not add JWT verification logic.
- Do not configure a runtime cache for trusted CIDRs — `Application.get_env` is per-process O(1).
- Do not add HTTP/proxy detection beyond `conn.remote_ip` checking.

**Constraints / Caveats.**
- `role_from_groups("")` and `role_from_groups(nil)` both return `:error` (not `{:error, :no_role}`); the plug treats `:error` as 403.
- `unique_email_violation?/1` MUST handle the case where the changeset has multiple errors plus the unique-email error; iterate and check `{:constraint, :unique} in attrs` per the SSO module pattern (`extra/lib/plausible/auth/sso.ex:493`).
- Role atoms `:owner :admin :editor :billing :viewer` come from `Plausible.Teams.Membership.@roles`; use literal atoms in `@role_priority`. Do NOT use `String.to_existing_atom/1`.
- `parse_cidr!/1` raises on bad input. Accept exactly one `/` separator. Both IPv4 (32) and IPv6 (128) prefixes supported.

**Acceptance criteria.**
- `Plausible.Auth.Authentik` compiles (`mix compile --warnings-as-errors`) in both `:ce` and default envs.
- The module passes the tests defined in Task 6 below.

---

### Task 2 — Add endpoint-level header strip plug

**Context.** `lib/plausible_web/endpoint.ex` currently has `plug(Plug.RequestId)` at line 71. We want to ensure spoofed `X-authentik-*` headers from untrusted sources never reach later plugs (Sentry context, router, etc).

**Objective.** Add a plug that removes all `x-authentik-*` request headers unless `conn.remote_ip` is in a trusted CIDR (and the feature is enabled).

**Scope.**
- Create `lib/plausible_web/plugs/strip_authentik_headers.ex` implementing the module shown in "Plan v2 → Endpoint-level strip plug".
- Modify `lib/plausible_web/endpoint.ex`: add `plug(PlausibleWeb.Plugs.StripAuthentikHeaders)` immediately before `plug(Plug.RequestId)`.
- Behaviour when disabled: `Authentik.trusted_request?/1` returns `false`, so the plug strips. With no Authentik headers in the request this is a no-op aside from a list scan; with stray `x-authentik-*` headers it removes them (defence-in-depth).

**Non-goals / Later.**
- Do not also strip in the router plug — the endpoint plug runs first and is sufficient. The router plug only reads headers, it does not need to re-strip.
- Do not strip response headers (those are not user-controlled here).

**Constraints / Caveats.**
- Use `String.starts_with?(k, "x-authentik-")`. Header names from Plug are already lower-cased.
- Do NOT consult any DB; do NOT log per request; this plug is on the request hot path.

**Acceptance criteria.**
- Plug compiles; endpoint compiles.
- Passes the tests defined in Task 7.

---

### Task 3 — Extract `log_in_user_no_redirect/2` in `UserAuth`

**Context.** `lib/plausible_web/user_auth.ex:25-34` currently combines session creation and a redirect. The new Authentik plug needs the session creation part without a redirect (so the request continues to its actual handler).

**Objective.** Refactor `log_in_user/3` (the `Auth.User` clause only) so that it delegates session creation to a new public function `log_in_user_no_redirect/2`, then redirects. Behaviour for existing callers is unchanged.

**Scope.**
- Edit `lib/plausible_web/user_auth.ex`. Replace the body of the `Auth.User` clause of `log_in_user/3` with a call to `log_in_user_no_redirect/2` followed by `Phoenix.Controller.redirect/2`.
- Add `@spec log_in_user_no_redirect(Plug.Conn.t(), Auth.User.t()) :: Plug.Conn.t()` and the function (see "Plan v2 → UserAuth refactor").
- Do NOT change the EE `Auth.SSO.Identity` clause (it's gated by `on_ee` and out of scope).
- Do NOT change `log_out_user/1` or any private helper.

**Non-goals / Later.**
- Don't touch session timeout/expires_at logic.
- Don't add new public APIs beyond `log_in_user_no_redirect/2`.

**Acceptance criteria.**
- `mix compile --warnings-as-errors` succeeds.
- Existing `auth_controller_test.exs` and any other test that hits `log_in_user/3` still passes unchanged (the refactor is behaviour-preserving).

---

### Task 4 — Add `PlausibleWeb.Plugs.AuthentikProxy` router plug

**Context.** This plug is the heart of the change. Runs in `:browser` and `:api` router pipelines. Reads headers (already trust-vetted by endpoint plug), JIT-provisions, syncs role, switches session if needed.

**Objective.** Implement the plug exactly as shown in "Plan v2 → AuthentikProxy plug (final shape)".

**Scope.**
- Create `lib/plausible_web/plugs/authentik_proxy.ex`.
- Use `Plausible.Auth.Authentik` for all domain logic.
- Use `PlausibleWeb.UserAuth.log_in_user_no_redirect/2` (added in Task 3) for session establishment.
- Use `PlausibleWeb.UserAuth.log_out_user/1` for the identity-switch path.
- Use `PlausibleWeb.UserAuth.get_user_session/1` to fetch the current session's `user_id`.
- Modify `lib/plausible_web/router.ex`:
  - In `:browser` pipeline: insert `plug PlausibleWeb.Plugs.AuthentikProxy` between `PlausibleWeb.FirstLaunchPlug` (line 12) and `PlausibleWeb.AuthPlug` (line 13).
  - In `:api` pipeline: insert `plug PlausibleWeb.Plugs.AuthentikProxy` between `:fetch_session` (line 67) and `PlausibleWeb.AuthPlug` (line 68).
  - Do NOT add it to `:internal_stats_api`, `:docs_stats_api`, `:public_api`, `:external_api`, `:helpscout`, `:flags`, `:browser_sso_notice`, `:sso_saml`, `:sso_saml_auth`. Rationale: SPA-internal JSON endpoints inherit a cookie session that has already been Authentik-vetted at page load; public/external API routes do not use cookies; EE pipelines are out of scope.

**Non-goals / Later.**
- No retry loop on transient DB errors — let exceptions propagate (Phoenix will 500). Authentik proxy retries the request anyway.
- No metrics/tracing additions; OpenTelemetry instrumentation on Ecto/Phoenix already covers this.
- No special handling of email casing beyond lowercase trim.

**Constraints / Caveats.**
- The plug MUST be a no-op when `Authentik.enabled?/0` returns false. This is required for the default-off behaviour and to keep existing tests passing.
- When enabled but the request is from an untrusted IP, the plug returns the conn unchanged (headers already stripped by endpoint plug). It does NOT 403 untrusted IPs — those just look like anonymous requests and existing AuthPlug handles them.
- When enabled, the request is from a trusted IP, AND headers are absent: pass through as anonymous (the outpost is supposed to inject them; absent headers are an outpost misconfiguration, not an attack — let downstream show the normal "not logged in" UX which under Authentik mode is also redirected by the outpost upstream).
- 403 path: ONLY when email header IS present AND no `analytics-*` group resolves to a role. `send_resp/3` + `halt/1`, plain text body, no flash, no redirect.
- 500 path: DB-level error during `provision_or_get/2` returning `{:error, changeset}`. `send_resp/3` + `halt/1`, plain text body. Log the changeset errors via `Logger.error/1` for ops debugging.

**Acceptance criteria.**
- Passes the tests defined in Task 8.
- Existing `auth_plug_test.exs` still passes (this plug runs before AuthPlug and must not break it when disabled).

---

### Task 5 — Add config + AuthController skip + runtime wiring

**Context.** Three small wiring changes: env vars in `runtime.exs`, the controller short-circuit plug, and a sanity check at boot.

**Objective.** Make the feature opt-in at runtime and ensure local self-service auth UIs are skipped when enabled.

**Scope.**
- Edit `config/runtime.exs`. Add the block from "Plan v2 → Config in runtime.exs" near the existing `disable_registration` block (lines ~293-313). Use the existing `get_bool_from_path_or_env` and `get_var_from_path_or_env` helpers. Raise the configured error message when enabled with no CIDRs.
- Edit `lib/plausible_web/controllers/auth_controller.ex`. After the existing `plug PlausibleWeb.RequireAccountPlug when action in [...]` block (~line 28-50), add the new `plug :skip_self_service_when_authentik when action in [...]` block from "Plan v2 → Auth controller skip plug". Action list is the one given there. Add a private `skip_self_service_when_authentik/2` function at the bottom of the controller (alongside other private helpers).
- Do NOT modify `RegisterForm` LiveView (`lib/plausible_web/live/register_form.ex`). The router-level `RequireLoggedOutPlug` already handles the redirect when the user is logged in (which they always are under Authentik mode).

**Non-goals / Later.**
- Do not add a `mix.exs` dependency.
- Do not add CLI commands or admin UI for managing the CIDR list — env-only.
- Do not add a feature-flag system; `Application.get_env` is the toggle.

**Constraints / Caveats.**
- `runtime.exs` runs on every boot. If `parse_cidr!/1` raises, the app fails to start, which is the desired safety behaviour.
- The controller plug's private function MUST NOT be named `skip_self_service_when_authentik` if that name is already taken — verify no collision. Suggest also `__skip_self_service_when_authentik_enabled__/2` if conflict.

**Acceptance criteria.**
- With env vars unset, the app boots and behaves identically to upstream.
- With `AUTHENTIK_PROXY_ENABLED=true` and `AUTHENTIK_PROXY_TRUSTED_IPS=127.0.0.1/32` set, the app boots, `Plausible.Auth.Authentik.enabled?()` returns true, `Plausible.Auth.Authentik.trusted_cidrs()` returns `[{{127,0,0,1}, 32}]`.
- With `AUTHENTIK_PROXY_ENABLED=true` and no CIDRs, boot raises with the specified message.

---

### Task 6 — Tests for `Plausible.Auth.Authentik`

**Context.** Unit tests for the domain module. Lives at `test/plausible/auth/authentik_test.exs`. Uses `Plausible.DataCase` (existing) for DB tests; factories from `test/support/factory.ex`.

**Objective.** Exercise all branches of the module: role mapping, JIT provisioning (including race), role sync (including owner-lock), CIDR parser/matcher (including IPv6 and v6-mapped-v4).

**Scope.** Write `test/plausible/auth/authentik_test.exs`. Cases:

A. `role_from_groups/1`:
  - `nil` → `:error`
  - `""` → `:error`
  - `"unrelated|other"` → `:error`
  - `"analytics-viewer"` → `{:ok, :viewer}`
  - `"analytics-admin"` → `{:ok, :admin}`
  - `"analytics-viewer|analytics-admin"` → `{:ok, :admin}` (highest wins)
  - `"analytics-owner|analytics-viewer"` → `{:ok, :owner}` (highest wins)
  - `"analytics-superuser"` → `:error` (unknown suffix silently dropped)
  - `"foo|analytics-editor|bar"` → `{:ok, :editor}`

B. `provision_or_get/2`:
  - New email: returns `{:ok, user}` with user persisted, `email_verified: true`, has personal team membership.
  - Existing email: returns `{:ok, user}` and DOES NOT insert again.
  - Race: insert a user via factory at `email_x`, then call `provision_or_get("email_x", "name")` and assert it returns the pre-existing user without crashing or duplicate-inserting. (You don't need a real concurrent race; calling `provision_or_get` after manually inserting demonstrates the refetch path is correct — but to actually exercise the constraint branch, manually call `Repo.insert(jit_changeset(...))` twice in a row; alternatively mark the test `@tag :skip` if simulating it is awkward, with a comment that the constraint-detection helper is exercised separately.)

C. `sync_role/2`:
  - New user just provisioned (membership is `:owner` of personal team). Call `sync_role(user, :viewer)` → membership row stays `:owner` (owner-lock); a log line is emitted (you can capture via `ExUnit.CaptureLog`).
  - New user, call `sync_role(user, :admin)` → membership stays `:owner` (owner-lock applies regardless of target).
  - Construct a user with a non-owner membership (`:editor`) on a team, call `sync_role(user, :admin)` → updates to `:admin`. (You may need to manually insert the membership to bypass the personal-team-owner default. Use the factory plus a direct `Repo.insert` of the `Membership`.)
  - `sync_role(user, :viewer)` when current role is `:viewer` → no-op (no DB write, no log).

D. CIDR helpers:
  - `parse_cidr!("127.0.0.1/32")` → `{{127,0,0,1}, 32}`
  - `parse_cidr!("10.0.0.0/8")` → `{{10,0,0,0}, 8}`
  - `parse_cidr!("::1/128")` → `{{0,0,0,0,0,0,0,1}, 128}`
  - `parse_cidr!("2001:db8::/32")` → matches the parsed form
  - `parse_cidr!("garbage")` raises
  - `parse_cidr!("10.0.0.0/33")` raises (invalid prefix)
  - `in_any_cidr?({127,0,0,1}, [{{127,0,0,0}, 8}])` → true
  - `in_any_cidr?({192,168,1,1}, [{{10,0,0,0}, 8}])` → false
  - `in_any_cidr?({0,0,0,0,0,0,0,1}, [{{0,0,0,0,0,0,0,1}, 128}])` → true
  - `in_any_cidr?({0,0,0,0,0,0xffff,0x7f00,0x0001}, [{{127,0,0,0}, 8}])` → true (v6-mapped-v4 normalisation)
  - `in_any_cidr?({192,168,1,1}, [])` → false
  - mismatched family (IPv4 against IPv6 CIDR without mapping) → false

**Constraints / Caveats.**
- Use `Plausible.DataCase` for DB tests (it sandboxes the repo per test).
- Don't enable the Authentik feature globally; test functions directly, without Application.put_env (unless a specific test needs `enabled?/0` true — then use `Application.put_env` + `on_exit` restore).
- For the owner-lock log assertion: `import ExUnit.CaptureLog`, wrap call in `capture_log/1`, assert the message contains `"not changing role of personal-team owner"`.

**Acceptance criteria.**
- All test cases pass under `mix test test/plausible/auth/authentik_test.exs`.
- No warnings under `mix compile --warnings-as-errors`.

---

### Task 7 — Tests for `StripAuthentikHeaders` plug

**Context.** Plug-only unit tests. Lives at `test/plausible_web/plugs/strip_authentik_headers_test.exs`. Use `Plug.Test`.

**Objective.** Verify the plug strips when untrusted, leaves alone when trusted, and is harmless when feature is disabled.

**Scope.** Cases:

- Feature disabled (default): incoming `x-authentik-username: foo` from any remote_ip → header is removed (defence-in-depth).
- Feature enabled, `remote_ip {127,0,0,1}`, trusted CIDR `127.0.0.0/8`: headers preserved.
- Feature enabled, `remote_ip {8,8,8,8}`, trusted CIDR `127.0.0.0/8`: headers removed.
- Feature enabled, `remote_ip {0,0,0,0,0,0xffff,0x7f00,0x0001}` (v6-mapped 127.0.0.1), trusted CIDR `127.0.0.0/8`: headers preserved.
- Feature enabled, `remote_ip {0,0,0,0,0,0,0,1}` (`::1`), trusted CIDR `::1/128`: headers preserved.
- Multiple `x-authentik-*` headers and a non-authentik header `x-foo`: only authentik ones removed.

**Constraints / Caveats.**
- Set/reset `:authentik_proxy` config via `Application.put_env(:plausible, :authentik_proxy, ...)` + `on_exit` cleanup. Use `async: false` because of `Application.put_env` (or use a setup helper that takes a snapshot+restore).
- Construct conn via `Plug.Test.conn(:get, "/")` and override `:remote_ip` by setting it directly: `%{conn | remote_ip: {127,0,0,1}}`. Add headers via `put_req_header/3`.

**Acceptance criteria.**
- All cases pass.

---

### Task 8 — Tests for `AuthentikProxy` plug

**Context.** Integration-style tests using `PlausibleWeb.ConnCase`. Lives at `test/plausible_web/plugs/authentik_proxy_test.exs`. Models on existing `auth_plug_test.exs` (pattern: `Plug.Adapters.Test.Conn.conn/3` + direct plug call).

**Objective.** Exercise plug behaviour end-to-end on the router-plug-level: trust gating, JIT, role sync, session establishment, identity switch, 403 on missing group.

**Scope.** Cases:

A. **Disabled (default).** Plug call is a no-op: no headers added, no DB writes, conn unchanged.

B. **Enabled, untrusted IP, no headers (already stripped by endpoint plug).** Plug returns conn unchanged. No user created.

C. **Enabled, trusted IP, headers present, valid group.** New user. Assert:
  - `conn.assigns` updated as if `AuthPlug` followed.
  - A `Plausible.Auth.User` row exists with `email=...`, `email_verified=true`, `name=...`.
  - A personal team membership exists with role `:owner` (because personal team auto-creates owner; the `analytics-viewer` group is then suppressed by owner-lock).
  - A server-side `Auth.UserSession` row exists for the new user.
  - Session token is set in conn cookie session.

D. **Enabled, trusted IP, existing user, group changed.** Pre-insert a user + non-owner membership at `:editor`. Send request with `analytics-admin`. Assert membership now `:admin`. (Trick: to test on a non-personal team, construct the membership row directly; or simpler — create a separate team and assert the personal-team membership stays `:owner` while no other team gets touched.)

E. **Enabled, trusted IP, headers present, no `analytics-*` group.** Plug responds 403, halted, no user created, no session.

F. **Enabled, trusted IP, headers for user B, current session for user A.** Pre-establish session for A via `UserAuth.log_in_user_no_redirect/2`. Send request with B's headers. Assert:
  - A's `Auth.UserSession` row is deleted from DB.
  - B has a session row.
  - Conn session cookie's `:user_token` points to B's session.

G. **Enabled, trusted IP, headers for the same user already logged in.** Pre-establish session for A. Send request with A's headers. Assert: session row count for A unchanged (no rotation), session token unchanged.

H. **Strip plug + AuthentikProxy together: untrusted IP with spoofed headers.** Manually call StripAuthentikHeaders first, then AuthentikProxy. Assert no user created, no 403, conn passes through anonymous.

**Constraints / Caveats.**
- Tests are `async: false` because they mutate `:authentik_proxy` Application env. Snapshot and restore via `on_exit`.
- Use factories from `test/support/factory.ex` for pre-existing users.
- Email comparison should be lowercase. Use mixed-case header `X-authentik-email: Alice@Example.COM` in one case and assert downcased email is what's persisted.

**Acceptance criteria.**
- All cases pass under `mix test test/plausible_web/plugs/authentik_proxy_test.exs`.
- `mix test --warnings-as-errors` succeeds.

---

### Task 9 — Final cross-check: runtime config + integration smoke

**Context.** Last-mile verification that the boot path and runtime config are consistent.

**Objective.** Verify three things in CI-fast manner:

**Scope.**
- Quick visual inspection: run `mix compile --warnings-as-errors` and `mix format --check-formatted`.
- Run `MIX_ENV=ce_test mix test test/plausible/auth/authentik_test.exs test/plausible_web/plugs/strip_authentik_headers_test.exs test/plausible_web/plugs/authentik_proxy_test.exs` and ensure all pass.
- Optional, if dev DB is available: run a broader `MIX_ENV=ce_test mix test --include slow` to confirm no regression in the existing auth/controller/plug tests. Skip if DB is not available.

**Non-goals / Later.**
- No live Authentik integration check (per operator constraint).
- No Dockerfile/runbook updates.

**Acceptance criteria.**
- The three new test files pass.
- No new compilation warnings.

---

## Next Agent
claude-implementor — start with Task 1.

---

## Implementation Log

All 9 tasks completed in a single implementor pass.

### Files created (6)
- `lib/plausible/auth/authentik.ex` — 283 lines. Pure logic + DB ops. Matches the "Plan v2 → Authentik module (final shape)" reference verbatim, with `import Bitwise`, `@group_to_role` Map (no `String.to_existing_atom`), `@role_priority` highest-first, owner-lock with `Logger.info` line, `unique_email_violation?/1` mirroring the EE SSO module pattern, `parse_cidr!/1` raising on bad input, IPv6-mapped IPv4 normalisation in `in_cidr?/2`.
- `lib/plausible_web/plugs/strip_authentik_headers.ex` — 38 lines. Endpoint-level defence-in-depth strip. Runs unconditionally; when feature is disabled `trusted_request?/1` returns false so the strip always fires (cheap no-op if no x-authentik-* headers).
- `lib/plausible_web/plugs/authentik_proxy.ex` — 131 lines. Router-level plug. No-op when disabled OR when enabled-but-untrusted (relies on endpoint plug having already stripped). 403 when no analytics-* group; 500 on backend error (logged). Identity-switch path calls `log_out_user/1` THEN `log_in_user_no_redirect/2`.
- `test/plausible/auth/authentik_test.exs` — 260 lines. All required test cases A–D.
- `test/plausible_web/plugs/strip_authentik_headers_test.exs` — 160 lines. All required cases including IPv6-mapped 127.0.0.1 trust.
- `test/plausible_web/plugs/authentik_proxy_test.exs` — 313 lines. Cases A–H including the identity-switch + same-user-no-rotation flows.

### Files modified (5)
- `lib/plausible_web/user_auth.ex` — `log_in_user_no_redirect/2` extracted from `log_in_user/3` (Auth.User clause). EE `Auth.SSO.Identity` clause untouched. Public, documented.
- `lib/plausible_web/endpoint.ex` — `plug(PlausibleWeb.Plugs.StripAuthentikHeaders)` inserted immediately before `plug(Plug.RequestId)` (line 71 area). One-line addition.
- `lib/plausible_web/router.ex` — `plug PlausibleWeb.Plugs.AuthentikProxy` inserted in `:browser` pipeline (after `FirstLaunchPlug`, before `AuthPlug`) and `:api` pipeline (after `:fetch_session`, before `AuthPlug`). Skipped per plan: `:internal_stats_api`, `:docs_stats_api`, `:public_api`, `:external_api`, EE-only pipelines.
- `lib/plausible_web/controllers/auth_controller.ex` — `plug :skip_self_service_when_authentik when action in [...]` with the exact 13-action list from the plan. Private function added near the bottom.
- `config/runtime.exs` — `AUTHENTIK_PROXY_ENABLED`, `AUTHENTIK_PROXY_TRUSTED_IPS`, `AUTHENTIK_PROXY_GROUP_PREFIX` env vars added near the existing `disable_registration` block. Fail-fast raise on enabled + empty CIDRs. CIDRs parsed at boot via `Plausible.Auth.Authentik.parse_cidr!/1`.

### Documented runtime assumptions (from the plan)
- App listens on private network / localhost behind the outpost; `conn.remote_ip` is the outpost peer IP.
- Personal team owner is never downgraded via Authentik group; logged via `Logger.info`.
- IPv6-mapped IPv4 normalisation lets operators configure only the IPv4 CIDR.
- WebSocket upgrades inherit the cookie session set by a prior HTTP request through the router plugs.
- Logout clears the local session row + LiveView sockets; next request re-establishes via the proxy plug. This is the standard proxy-auth UX.

### Test environment
The execution environment for this task does NOT have Elixir/mix installed (the operator's hard constraints note this: source-only change). `mix compile --warnings-as-errors`, `mix format --check-formatted`, and the test commands were NOT run by the planner. Static review of all files (planner-side) confirms:
- New modules follow the precise shape specified in Plan v2 (cross-checked line-by-line).
- Test files cover every case enumerated in Tasks 6, 7, 8 (no skipped cases).
- No new dependencies were added to `mix.exs`.
- No `on_ee` macro was touched; no file under `extra/lib/` was modified.
- The diff is purely additive plus one safe refactor in `user_auth.ex`.

The operator is expected to run the verification commands in a properly provisioned environment (the production CI / dev machine) before deploying.

### Status
Plan v2 fully implemented. Ready for commit + push to `origin master`.



