<script lang="ts">
  import { api, client } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";
  import type { Credential } from "./types.ts";

  let {
    credential,
    onclose,
    ondone,
  }: {
    credential: Credential | null;
    onclose: () => void;
    ondone: () => void;
  } = $props();

  let label = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);

  // Start from the current label each time the dialog opens.
  $effect(() => {
    if (credential) {
      label = credential.label;
      error = null;
    }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!credential || busy) return;
    busy = true;
    error = null;
    const result = await api(
      client.POST(
        "/-/google-credentials/api/credentials/{credential_id}/rename",
        {
          params: { path: { credential_id: credential.id } },
          body: { label },
        },
      ),
    );
    busy = false;
    if (result.data) {
      ondone();
    } else {
      error = result.errorMessage ?? "Couldn't rename it";
    }
  }
</script>

<Modal open={credential !== null} {busy} title="Rename" {onclose}>
  <form id="rename-credential" onsubmit={submit}>
    <label for="rename-label">Label</label>
    <input
      id="rename-label"
      type="text"
      bind:value={label}
      disabled={busy}
      maxlength="200"
      required
    />
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
  </form>

  {#snippet footer({ requestClose })}
    <button
      type="button"
      class="modal-btn modal-btn-ghost"
      disabled={busy}
      onclick={requestClose}>Cancel</button
    >
    <button
      type="submit"
      form="rename-credential"
      class="modal-btn modal-btn-primary"
      disabled={busy || !label.trim()}
    >
      Save
    </button>
  {/snippet}
</Modal>

<style>
  label {
    display: block;
    font-weight: bold;
    margin-bottom: 0.25rem;
  }
  input {
    width: 100%;
    box-sizing: border-box;
  }
  .error {
    color: #b42318;
  }
</style>
