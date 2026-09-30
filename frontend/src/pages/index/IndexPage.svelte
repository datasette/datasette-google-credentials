<script lang="ts">
  import { api, client } from "../../lib/api.ts";
  import type { IndexPageData } from "../../page_data/IndexPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import AddServiceAccountDialog from "./AddServiceAccountDialog.svelte";
  import DeleteDialog from "./DeleteDialog.svelte";
  import GoogleAccounts from "./GoogleAccounts.svelte";
  import RenameDialog from "./RenameDialog.svelte";
  import RotateKeyDialog from "./RotateKeyDialog.svelte";
  import ServiceAccounts from "./ServiceAccounts.svelte";
  import SetupNotices from "./SetupNotices.svelte";
  import type { Credential, Notice } from "./types.ts";

  // After Connect Google, the callback's result arrives as a Datasette flash
  // message (rendered by base.html above this app), not as query params.
  const pageData = loadPageData<IndexPageData>();
  const status = pageData.status;
  const actorJson = JSON.stringify({ id: pageData.actor_id });

  let credentials = $state<Credential[]>(pageData.credentials);
  let notices = $state<Notice[]>([]);
  let highlightId = $state<string | null>(null);

  // Dialogs: each is open while its target is set.
  let adding = $state(false);
  let renaming = $state<Credential | null>(null);
  let rotating = $state<Credential | null>(null);
  let deleting = $state<Credential | null>(null);

  const accounts = $derived(
    credentials.filter((c) => c.type === "google_oauth"),
  );
  const serviceAccounts = $derived(
    credentials.filter((c) => c.type === "service_account"),
  );

  // Saving needs an encryption key; connecting also needs an OAuth client.
  const canConnect =
    status.can_connect &&
    status.oauth_configured &&
    status.encryption_configured;
  const canAdd = status.can_add_service_account && status.encryption_configured;
  const showAccounts = $derived(status.can_connect || accounts.length > 0);
  const showServiceAccounts = $derived(
    status.can_add_service_account || serviceAccounts.length > 0,
  );

  async function refresh() {
    const result = await api(client.GET("/-/google-auth/api/credentials"));
    if (result.data) {
      credentials = result.data.credentials;
    } else {
      notice("error", `Couldn't reload the list: ${result.errorMessage}`);
    }
  }

  function notice(kind: Notice["kind"], text: string) {
    notices = [...notices, { kind, text }];
  }
</script>

<div class="google-auth-page">
  <h1>Google accounts</h1>

  <SetupNotices {status} />

  {#each notices as n, i (i)}
    <p class="message-{n.kind}">
      {n.text}
      <button
        type="button"
        class="dismiss"
        aria-label="Dismiss"
        onclick={() => (notices = notices.filter((_, j) => j !== i))}>×</button
      >
    </p>
  {/each}

  {#if showAccounts}
    <GoogleAccounts
      {accounts}
      {canConnect}
      connectUrl={pageData.connect_url}
      onrename={(c) => (renaming = c)}
      ondisconnect={(c) => (deleting = c)}
    />
  {/if}

  {#if showServiceAccounts}
    <ServiceAccounts
      accounts={serviceAccounts}
      {canAdd}
      {highlightId}
      share={pageData.share}
      {actorJson}
      onadd={() => (adding = true)}
      onrename={(c) => (renaming = c)}
      onrotate={(c) => (rotating = c)}
      ondelete={(c) => (deleting = c)}
      onsharechanged={refresh}
    />
  {/if}

  {#if !showAccounts && !showServiceAccounts}
    <p class="empty">
      You don't have any Google credentials. When someone shares a service
      account with you, it appears here.
    </p>
  {/if}
</div>

<AddServiceAccountDialog
  open={adding}
  onclose={() => (adding = false)}
  onadded={(id) => {
    highlightId = id;
    refresh();
  }}
/>
<RenameDialog
  credential={renaming}
  onclose={() => (renaming = null)}
  ondone={() => {
    renaming = null;
    refresh();
  }}
/>
<RotateKeyDialog
  credential={rotating}
  onclose={() => (rotating = null)}
  ondone={(message) => {
    rotating = null;
    notice("info", message);
    refresh();
  }}
/>
<DeleteDialog
  credential={deleting}
  onclose={() => (deleting = null)}
  ondeleted={refresh}
/>
