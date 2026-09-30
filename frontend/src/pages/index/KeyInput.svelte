<script lang="ts">
  import { describeKey } from "../../lib/format.ts";

  /**
   * The service-account key: paste it or pick the downloaded .json file.
   * The file is read here, client-side, into `value` (sent as `key_json`).
   * Owners clear `value` once it's been accepted; this component keeps no
   * other copy (the file input is reset after reading).
   */
  let {
    value = $bindable(""),
    disabled = false,
    id,
  }: { value?: string; disabled?: boolean; id: string } = $props();

  let fileError = $state<string | null>(null);
  const peek = $derived(describeKey(value));

  async function readFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    fileError = null;
    if (!file) return;
    if (file.size > 16 * 1024) {
      fileError = "That file is too big to be a service account key.";
      return;
    }
    try {
      value = await file.text();
    } catch {
      fileError = "Couldn't read that file.";
    }
  }
</script>

<label for={id}>JSON key</label>
<textarea
  {id}
  bind:value
  {disabled}
  rows="6"
  autocomplete="off"
  spellcheck="false"
  placeholder={'{"type": "service_account", "client_email": "…", "private_key": "…", …}'}
></textarea>
<p class="file">
  <label>
    Or choose the key file:
    <input
      type="file"
      accept=".json,application/json"
      {disabled}
      onchange={readFile}
    />
  </label>
</p>
{#if fileError}
  <p class="problem">{fileError}</p>
{:else if peek && "email" in peek}
  <p class="peek">Key for <code>{peek.email}</code></p>
{:else if peek && "problem" in peek}
  <p class="problem">{peek.problem}</p>
{/if}

<style>
  label {
    display: block;
    font-weight: bold;
    margin-bottom: 0.25rem;
  }
  .file label {
    font-weight: normal;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    font-family: monospace;
    font-size: 0.8rem;
  }
  .peek {
    color: #1a7f37;
  }
  .problem {
    color: #b42318;
  }
</style>
