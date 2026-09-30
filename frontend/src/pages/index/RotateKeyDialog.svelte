<script lang="ts">
  import { api, client } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";
  import type { Credential } from "./types.ts";
  import KeyInput from "./KeyInput.svelte";

  let {
    credential,
    onclose,
    ondone,
  }: {
    /** The service account to rotate; null when the dialog is closed. */
    credential: Credential | null;
    onclose: () => void;
    ondone: (message: string) => void;
  } = $props();

  let keyJson = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!credential || busy || !keyJson.trim()) return;
    busy = true;
    error = null;
    const result = await api(
      client.POST("/-/google-auth/api/credentials/{credential_id}/rotate-key", {
        params: { path: { credential_id: credential.id } },
        body: { key_json: keyJson },
      }),
    );
    busy = false;
    if (result.data) {
      keyJson = "";
      ondone(
        `Rotated the key for ${result.data.label}. Delete the old key in the Cloud console once nothing uses it.`,
      );
    } else {
      error = result.errorMessage ?? "Couldn't rotate the key";
    }
  }

  function closed() {
    keyJson = "";
    error = null;
    onclose();
  }
</script>

<Modal open={credential !== null} {busy} title="Rotate key" onclose={closed}>
  {#if credential}
    <form id="rotate-key" onsubmit={submit}>
      <p class="hint">
        Create a new JSON key for <code>{credential.google_email}</code> in the Cloud
        console and paste or choose it here. It must be for the same service account.
        Datasette tests it with Google before replacing the old one.
      </p>
      <KeyInput id="rotate-key-json" bind:value={keyJson} disabled={busy} />
      {#if busy}
        <p role="status">Testing the key with Google…</p>
      {:else if error}
        <p class="error" role="alert">{error}</p>
      {/if}
    </form>
  {/if}

  {#snippet footer({ requestClose })}
    <button
      type="button"
      class="modal-btn modal-btn-ghost"
      disabled={busy}
      onclick={requestClose}>Cancel</button
    >
    <button
      type="submit"
      form="rotate-key"
      class="modal-btn modal-btn-primary"
      disabled={busy || !keyJson.trim()}
    >
      {busy ? "Testing…" : "Test and replace"}
    </button>
  {/snippet}
</Modal>

<style>
  .hint {
    color: #555;
  }
  .error {
    color: #b42318;
  }
</style>
