<script lang="ts">
  import { api, client } from "../../lib/api.ts";
  import DeleteDialog from "../../lib/DeleteDialog.svelte";
  import { formatTimestamp, shortScope } from "../../lib/format.ts";
  import SetupNotices from "../../lib/SetupNotices.svelte";
  import type {
    AdminCredentialInfo,
    AdminPageData,
  } from "../../page_data/AdminPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";

  /**
   * Every credential, for `google-auth-admin` holders (D6): list and delete,
   * for offboarding and incidents. Deliberately no use, rename or reconnect:
   * an admin can never act as someone else's Google account.
   *
   * Filters run in the browser over the full list and are mirrored in the
   * query string, so `?owner=bob` links straight to one person's credentials.
   */
  const pageData = loadPageData<AdminPageData>();
  const status = pageData.status;

  const TYPES: Record<string, string> = {
    google_oauth: "Google account",
    service_account: "Service account",
  };
  const STATUSES: Record<string, string> = { ok: "OK", broken: "Broken" };

  let credentials = $state<AdminCredentialInfo[]>(pageData.credentials);
  let names = $state<Record<string, string>>(pageData.actor_names);
  let loadError = $state<string | null>(null);
  let deleting = $state<AdminCredentialInfo | null>(null);

  const initial = new URLSearchParams(location.search);
  let owner = $state(initial.get("owner") ?? "");
  let type = $state(initial.get("type") ?? "");
  let statusFilter = $state(initial.get("status") ?? "");

  const owners = $derived(
    [...new Set(credentials.map((c) => c.owner_id))].sort((a, b) =>
      displayName(a).localeCompare(displayName(b)),
    ),
  );
  const shown = $derived(
    credentials.filter(
      (c) =>
        (!owner || c.owner_id === owner) &&
        (!type || c.type === type) &&
        (!statusFilter || c.status === statusFilter),
    ),
  );
  const filtered = $derived(Boolean(owner || type || statusFilter));

  $effect(() => {
    const params = new URLSearchParams(location.search);
    const filters: [string, string][] = [
      ["owner", owner],
      ["type", type],
      ["status", statusFilter],
    ];
    for (const [key, value] of filters) {
      if (value) params.set(key, value);
      else params.delete(key);
    }
    const query = params.toString();
    history.replaceState(
      history.state,
      "",
      location.pathname + (query ? `?${query}` : ""),
    );
  });

  function displayName(actorId: string): string {
    return names[actorId] ?? actorId;
  }

  function clearFilters() {
    owner = "";
    type = "";
    statusFilter = "";
  }

  async function refresh() {
    const result = await api(
      client.GET("/-/google-auth/api/admin/credentials"),
    );
    if (result.data) {
      credentials = result.data.credentials;
      names = result.data.actor_names;
      loadError = null;
    } else {
      loadError = `Couldn't reload the list: ${result.errorMessage}`;
    }
  }
</script>

{#snippet actor(actorId: string | null)}
  {#if !actorId}
    <span class="small">—</span>
  {:else if names[actorId]}
    {names[actorId]} <span class="small">({actorId})</span>
  {:else}
    {actorId}
  {/if}
{/snippet}

<div class="google-auth-page admin-page">
  <h1>All Google credentials</h1>

  <p>
    Every Google account and service account anyone has added to this Datasette.
    You can delete any of them, for example when someone leaves or a key leaks,
    but you can't use someone else's credentials.
    <a href={pageData.manage_url}>Manage your own Google accounts</a>.
  </p>

  <SetupNotices {status} />

  {#if loadError}
    <p class="message-error">
      {loadError}
      <button
        type="button"
        class="dismiss"
        aria-label="Dismiss"
        onclick={() => (loadError = null)}>×</button
      >
    </p>
  {/if}

  {#if credentials.length === 0}
    <p class="empty">Nobody has added any Google credentials yet.</p>
  {:else}
    <form class="filters" onsubmit={(event) => event.preventDefault()}>
      <label>
        Owner
        <select bind:value={owner}>
          <option value="">Anyone</option>
          {#each owners as ownerId (ownerId)}
            <option value={ownerId}
              >{displayName(ownerId)}{names[ownerId]
                ? ` (${ownerId})`
                : ""}</option
            >
          {/each}
          {#if owner && !owners.includes(owner)}
            <option value={owner}>{owner}</option>
          {/if}
        </select>
      </label>
      <label>
        Type
        <select bind:value={type}>
          <option value="">Any</option>
          {#each Object.entries(TYPES) as [value, label] (value)}
            <option {value}>{label}</option>
          {/each}
        </select>
      </label>
      <label>
        Status
        <select bind:value={statusFilter}>
          <option value="">Any</option>
          {#each Object.entries(STATUSES) as [value, label] (value)}
            <option {value}>{label}</option>
          {/each}
        </select>
      </label>
      <span class="small">
        {shown.length === credentials.length
          ? `${credentials.length} credential${credentials.length === 1 ? "" : "s"}`
          : `${shown.length} of ${credentials.length}`}
      </span>
      {#if filtered}
        <button type="button" class="link" onclick={clearFilters}
          >Clear filters</button
        >
      {/if}
    </form>

    {#if shown.length === 0}
      <p class="empty">No credentials match these filters.</p>
    {:else}
      <div class="table-wrap">
        <table class="rows-and-columns">
          <thead>
            <tr>
              <th scope="col">Credential</th>
              <th scope="col">Type</th>
              <th scope="col">Owner</th>
              <th scope="col">Status</th>
              <th scope="col">Access</th>
              <th scope="col">Last used</th>
              <th scope="col">Added by</th>
              <th scope="col"><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {#each shown as credential (credential.id)}
              <tr>
                <td>
                  <strong>{credential.label}</strong>
                  {#if credential.google_email && credential.google_email !== credential.label}
                    <br /><span class="email">{credential.google_email}</span>
                  {/if}
                  {#if credential.is_owner}
                    <span class="badge">Yours</span>
                  {/if}
                </td>
                <td>{TYPES[credential.type] ?? credential.type}</td>
                <td>{@render actor(credential.owner_id)}</td>
                <td>
                  {#if credential.status === "broken"}
                    <span class="badge badge-broken">Broken</span>
                    {#if credential.status_detail}
                      <br /><span class="small">{credential.status_detail}</span
                      >
                    {/if}
                  {:else}
                    {STATUSES[credential.status] ?? credential.status}
                  {/if}
                </td>
                <td>
                  {#if credential.type === "google_oauth"}
                    {credential.scopes.length
                      ? credential.scopes.map(shortScope).join(", ")
                      : "None"}
                  {:else}
                    <span class="small">Scopes chosen per use</span>
                  {/if}
                </td>
                <td>
                  {formatTimestamp(credential.last_used_at)}
                  {#if credential.last_used_by}
                    <br /><span class="small"
                      >by {@render actor(credential.last_used_by)}</span
                    >
                  {/if}
                </td>
                <td>{@render actor(credential.created_by)}</td>
                <td>
                  <button
                    type="button"
                    class="button"
                    onclick={() => (deleting = credential)}>Delete</button
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>

<DeleteDialog
  credential={deleting}
  owner={deleting && !deleting.is_owner ? displayName(deleting.owner_id) : null}
  onclose={() => (deleting = null)}
  ondeleted={refresh}
/>

<style>
  .admin-page {
    max-width: none;
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1rem;
    align-items: center;
    margin: 1rem 0;
  }
  .filters label {
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }
  .table-wrap {
    overflow-x: auto;
  }
  td {
    vertical-align: top;
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: inherit;
    text-decoration: underline;
    cursor: pointer;
    font: inherit;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
