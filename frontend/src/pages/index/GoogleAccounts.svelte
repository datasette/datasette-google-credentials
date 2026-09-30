<script lang="ts">
  import { formatTimestamp, shortScope } from "../../lib/format.ts";
  import type { Credential } from "./types.ts";

  /** Your own OAuth connections (owner-only, never shared: D6). */
  let {
    accounts,
    canConnect,
    connectUrl,
    onrename,
    ondisconnect,
  }: {
    accounts: Credential[];
    /** Connect / Reconnect are available (permission + OAuth + encryption set up). */
    canConnect: boolean;
    connectUrl: string;
    onrename: (credential: Credential) => void;
    ondisconnect: (credential: Credential) => void;
  } = $props();
</script>

<section>
  <div class="heading">
    <h2>Your Google accounts</h2>
    {#if canConnect}
      <a class="button" href={connectUrl}>Connect Google</a>
    {/if}
  </div>

  {#if accounts.length === 0}
    <p class="empty">
      {canConnect
        ? "No Google accounts connected yet. Connect one to import from and export to the spreadsheets it can see."
        : "No Google accounts connected."}
    </p>
  {:else}
    <ul class="cards">
      {#each accounts as account (account.id)}
        <li class="card">
          <div class="title">
            <strong>{account.label}</strong>
            {#if account.google_email && account.google_email !== account.label}
              <span class="email">{account.google_email}</span>
            {/if}
            {#if account.status === "broken"}
              <span class="badge badge-broken">Broken</span>
            {:else if account.missing_scopes.length}
              <span class="badge badge-limited">Limited access</span>
            {/if}
          </div>

          {#if account.status === "broken"}
            <p class="problem">
              {account.status_detail ??
                "Google stopped accepting this connection."}
              {#if canConnect}Reconnect to fix it.{/if}
            </p>
          {:else if account.missing_scopes.length}
            <p class="problem">
              Google didn't grant everything Datasette asks for (missing:
              {account.missing_scopes.map(shortScope).join(", ")}).
              {#if canConnect}Reconnect and tick every box to fix it.{/if}
            </p>
          {/if}

          <dl>
            <dt>Access</dt>
            <dd>
              {account.scopes.length
                ? account.scopes.map(shortScope).join(", ")
                : "None"}
            </dd>
            <dt>Last used</dt>
            <dd>{formatTimestamp(account.last_used_at)}</dd>
          </dl>

          <div class="actions">
            {#if canConnect && (account.status === "broken" || account.missing_scopes.length)}
              <a class="button" href={connectUrl}>Reconnect</a>
            {/if}
            {#if account.can_edit}
              <button type="button" onclick={() => onrename(account)}
                >Rename</button
              >
            {/if}
            {#if account.can_manage}
              <button type="button" onclick={() => ondisconnect(account)}
                >Disconnect</button
              >
            {/if}
          </div>
        </li>
      {/each}
    </ul>
    {#if canConnect}
      <p class="small">
        To reconnect, pick the same Google account when Google asks: the
        connection is updated in place.
      </p>
    {/if}
  {/if}
</section>
