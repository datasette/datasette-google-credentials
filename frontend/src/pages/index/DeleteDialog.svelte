<script lang="ts">
  import type { paths } from "../../../api.d.ts";
  import { api, client } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";
  import type { Credential } from "./types.ts";

  type DeleteResult =
    paths["/-/google-auth/api/credentials/{credential_id}/delete"]["post"]["responses"][200]["content"]["application/json"];

  /**
   * Disconnect (OAuth) or delete (service account): confirm, then report
   * what happened at Google (D16): whether the refresh token was revoked,
   * or which key to delete in the Cloud console.
   */
  let {
    credential,
    onclose,
    ondeleted,
  }: {
    credential: Credential | null;
    onclose: () => void;
    ondeleted: () => void;
  } = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state<DeleteResult | null>(null);

  const isOAuth = $derived(credential?.type === "google_oauth");
  const title = $derived(
    result
      ? isOAuth
        ? "Disconnected"
        : "Deleted"
      : isOAuth
        ? "Disconnect Google account"
        : "Delete service account",
  );

  async function confirm() {
    if (!credential || busy) return;
    busy = true;
    error = null;
    const response = await api(
      client.POST("/-/google-auth/api/credentials/{credential_id}/delete", {
        params: { path: { credential_id: credential.id } },
      }),
    );
    busy = false;
    if (response.data) {
      result = response.data;
      ondeleted();
    } else {
      error = response.errorMessage ?? "Couldn't delete it";
    }
  }

  function closed() {
    result = null;
    error = null;
    onclose();
  }
</script>

<Modal open={credential !== null} {busy} {title} onclose={closed}>
  {#if credential && result}
    {#if isOAuth}
      {#if result.revoked}
        <p>
          <strong>{credential.label}</strong> is disconnected and Google confirmed
          that Datasette's access is revoked.
        </p>
      {:else}
        <p>
          <strong>{credential.label}</strong> is disconnected from Datasette,
          but Google didn't confirm revoking its access{result.revoke_error
            ? ` (${result.revoke_error})`
            : ""}.
        </p>
        <p>
          To be sure, remove Datasette's access at
          <a
            href="https://myaccount.google.com/permissions"
            target="_blank"
            rel="noopener">myaccount.google.com/permissions</a
          >.
        </p>
      {/if}
    {:else}
      <p><strong>{credential.label}</strong> is deleted from Datasette.</p>
      <p class="follow-up">
        Its key still works at Google until you delete it:
        {#if result.private_key_id}
          delete key <code>{result.private_key_id}</code>
          {#if result.project_id}in project <code>{result.project_id}</code
            >{/if}
        {:else}
          delete the key
        {/if}
        of <code>{result.client_email ?? credential.google_email}</code>
        {#if result.cloud_console_url}
          in the
          <a href={result.cloud_console_url} target="_blank" rel="noopener"
            >Cloud console</a
          >.
        {:else}
          in the Cloud console.
        {/if}
      </p>
    {/if}
  {:else if credential}
    {#if isOAuth}
      <p>
        Disconnect <strong>{credential.label}</strong>? Datasette asks Google to
        revoke its access, then forgets it. Anything using it stops working; you
        can connect it again later.
      </p>
    {:else}
      <p>
        Delete <strong>{credential.label}</strong>
        (<code>{credential.google_email}</code>)? Everyone it's shared with
        loses access to it. This can't be undone.
      </p>
    {/if}
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
  {/if}

  {#snippet footer({ requestClose })}
    {#if result}
      <button
        type="button"
        class="modal-btn modal-btn-primary"
        onclick={requestClose}>Done</button
      >
    {:else}
      <button
        type="button"
        class="modal-btn modal-btn-ghost"
        disabled={busy}
        onclick={requestClose}>Cancel</button
      >
      <button
        type="button"
        class="modal-btn modal-btn-primary danger"
        disabled={busy}
        onclick={confirm}
      >
        {busy ? "Working…" : isOAuth ? "Disconnect" : "Delete"}
      </button>
    {/if}
  {/snippet}
</Modal>

<style>
  .error {
    color: #b42318;
  }
  .follow-up {
    background: #fff8c5;
    border: 1px solid #d4a72c;
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
  }
  .danger {
    background: #b42318;
    border-color: #b42318;
  }
</style>
