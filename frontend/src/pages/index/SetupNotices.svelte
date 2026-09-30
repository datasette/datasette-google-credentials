<script lang="ts">
  import type { StatusResponse } from "../../page_data/IndexPageData.types.ts";
  import CopyButton from "../../lib/CopyButton.svelte";

  /**
   * Setup notices, shown only when something is missing. The fixes (config
   * snippets, the redirect URI) are for people who can apply them: admins,
   * which includes root under `--root` (it holds every action).
   */
  let { status }: { status: StatusResponse } = $props();

  const encryptionSnippet = `plugins:
  datasette-google-auth:
    encryption-key:
      $env: DATASETTE_GOOGLE_AUTH_KEY`;

  const oauthSnippet = `plugins:
  datasette-google-auth:
    client_id:
      $env: DATASETTE_GOOGLE_AUTH_CLIENT_ID
    client_secret:
      $env: DATASETTE_GOOGLE_AUTH_CLIENT_SECRET`;
</script>

{#if !status.encryption_configured}
  <div class="notice notice-error">
    {#if status.is_admin}
      <h3>Credentials can't be saved until an encryption key is configured</h3>
      <p>Google credentials are stored encrypted. Generate a key:</p>
      <pre>datasette google-auth generate-key</pre>
      <p>
        Put it in the <code>DATASETTE_GOOGLE_AUTH_KEY</code> environment
        variable, add this to <code>datasette.yaml</code>, then restart
        Datasette:
      </p>
      <pre>{encryptionSnippet}</pre>
      <p class="small">
        Keep the key safe: without it, stored credentials can't be read.
      </p>
    {:else}
      <p>
        Google accounts aren't configured on this Datasette yet. Ask an admin to
        finish setting them up.
      </p>
    {/if}
  </div>
{/if}

{#if !status.oauth_configured && (status.is_admin || status.can_connect)}
  <div class="notice notice-warning">
    {#if status.is_admin}
      <h3>Connect Google isn't set up</h3>
      <p>
        People can't connect their own Google accounts until Datasette has an
        OAuth client. Service accounts work without one.
      </p>
      <ol>
        <li>
          In the Google Cloud console, open <em
            >APIs &amp; Services → Credentials</em
          >
          and create an <em>OAuth client ID</em> of type
          <em>Web application</em>.
        </li>
        <li>
          Add this exact <strong>Authorized redirect URI</strong>:
          <p class="uri">
            <code>{status.redirect_uri}</code>
            <CopyButton text={status.redirect_uri} />
          </p>
        </li>
        <li>
          Put the client ID and secret in environment variables, add this to
          <code>datasette.yaml</code>, then restart Datasette:
          <pre>{oauthSnippet}</pre>
        </li>
      </ol>
    {:else}
      <p>
        Connecting your own Google account isn't set up on this Datasette yet.
        Ask an admin{status.encryption_configured
          ? ", or use a service account"
          : ""}.
      </p>
    {/if}
  </div>
{/if}

{#if !status.internal_db_persistent}
  <div class="notice notice-warning">
    <p>
      <strong>Credentials will be lost on restart.</strong> Datasette is running
      without a persistent internal database{status.is_admin
        ? ""
        : ", so anything saved here disappears when it restarts"}.
    </p>
    {#if status.is_admin}
      <p>Run it with <code>--internal internal.db</code> to keep them.</p>
    {/if}
  </div>
{/if}

<style>
  .notice {
    border-radius: 6px;
    padding: 0.5rem 1rem;
    margin: 0 0 1rem;
    border: 1px solid;
  }
  .notice-error {
    background: #fff1f0;
    border-color: #f5b5ae;
  }
  .notice-warning {
    background: #fff8c5;
    border-color: #d4a72c;
  }
  .notice h3 {
    margin: 0.5rem 0;
    font-size: 1rem;
  }
  ol {
    list-style: decimal;
    padding-left: 1.5rem;
  }
  ol li {
    margin: 0.4rem 0;
  }
  pre {
    background: rgba(0, 0, 0, 0.05);
    padding: 0.5rem;
    overflow-x: auto;
  }
  .uri code {
    font-weight: bold;
    word-break: break-all;
  }
  .small {
    font-size: 0.85rem;
  }
</style>
