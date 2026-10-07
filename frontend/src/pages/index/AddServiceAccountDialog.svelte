<script lang="ts">
  import { api, client } from "../../lib/api.ts";
  import CopyButton from "../../lib/CopyButton.svelte";
  import Modal from "../../lib/Modal.svelte";
  import KeyInput from "./KeyInput.svelte";

  let {
    open,
    onclose,
    onadded,
  }: {
    open: boolean;
    onclose: () => void;
    /** A service account was saved (refresh the list, highlight it). */
    onadded: (id: string) => void;
  } = $props();

  let label = $state("");
  let keyJson = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  /** Set once Google accepted the key and it's saved. */
  let added = $state<{ email: string; label: string } | null>(null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !keyJson.trim()) return;
    busy = true;
    error = null;
    const result = await api(
      client.POST("/-/google-credentials/api/service-accounts", {
        body: { label, key_json: keyJson },
      }),
    );
    busy = false;
    if (result.data) {
      // The key is saved and encrypted server-side: drop every copy here.
      keyJson = "";
      label = "";
      added = { email: result.data.share_with_email, label: result.data.label };
      onadded(result.data.id);
    } else {
      error = result.errorMessage ?? "Couldn't add the service account";
    }
  }

  function closed() {
    // Never keep a key around in a closed dialog, saved or not.
    keyJson = "";
    label = "";
    error = null;
    added = null;
    onclose();
  }
</script>

<Modal {open} {busy} title="Add a service account" onclose={closed}>
  {#if added}
    <p>
      Google accepted the key and <strong>{added.label}</strong> is saved.
    </p>
    <div class="share-with" role="status">
      <p>Share your spreadsheet with this address:</p>
      <p class="email">
        <code>{added.email}</code>
        <CopyButton text={added.email} />
      </p>
    </div>
    <p class="hint">
      In Google Sheets, click <em>Share</em> and add it: as a Viewer to import from
      a sheet, as an Editor to export into one.
    </p>
  {:else}
    <form id="add-service-account" onsubmit={submit}>
      <p class="hint">
        In the Google Cloud console, create a key for the service account (<em
          >Keys → Add key → Create new key → JSON</em
        >) and paste or choose the downloaded file. Datasette tests it with
        Google, then stores it encrypted; nobody can read it back.
      </p>
      <label for="add-sa-label"
        >Label <span class="optional">(optional)</span></label
      >
      <input
        id="add-sa-label"
        type="text"
        bind:value={label}
        disabled={busy}
        maxlength="200"
        placeholder="Defaults to the service account's email"
      />
      <KeyInput id="add-sa-key" bind:value={keyJson} disabled={busy} />
      {#if busy}
        <p role="status">Testing the key with Google…</p>
      {:else if error}
        <p class="error" role="alert">{error}</p>
      {/if}
    </form>
  {/if}

  {#snippet footer({ requestClose })}
    {#if added}
      <button
        type="button"
        class="modal-btn modal-btn-primary"
        onclick={requestClose}
      >
        Done
      </button>
    {:else}
      <button
        type="button"
        class="modal-btn modal-btn-ghost"
        disabled={busy}
        onclick={requestClose}>Cancel</button
      >
      <button
        type="submit"
        form="add-service-account"
        class="modal-btn modal-btn-primary"
        disabled={busy || !keyJson.trim()}
      >
        {busy ? "Testing…" : "Test and save"}
      </button>
    {/if}
  {/snippet}
</Modal>

<style>
  label {
    display: block;
    font-weight: bold;
    margin: 0.75rem 0 0.25rem;
  }
  .optional {
    font-weight: normal;
    color: #666;
  }
  input[type="text"] {
    width: 100%;
    box-sizing: border-box;
  }
  .hint {
    color: #555;
  }
  .error {
    color: #b42318;
  }
  .share-with {
    background: #fff8c5;
    border: 1px solid #d4a72c;
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
  }
  .share-with p {
    margin: 0.25rem 0;
  }
  .email code {
    font-size: 1.05rem;
    font-weight: bold;
  }
</style>
