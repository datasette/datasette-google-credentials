<script lang="ts">
  import CopyButton from "../../lib/CopyButton.svelte";
  import { formatTimestamp } from "../../lib/format.ts";
  import type { ShareDialog } from "../../page_data/IndexPageData.types.ts";
  import type { Credential } from "./types.ts";

  /** Service accounts you can use: your own and those shared with you. */
  let {
    accounts,
    canAdd,
    highlightId,
    share,
    actorJson,
    onadd,
    onrename,
    onrotate,
    ondelete,
    onsharechanged,
  }: {
    accounts: Credential[];
    canAdd: boolean;
    /** Just added: highlighted and scrolled to. */
    highlightId: string | null;
    /** Null when datasette-acl-share's bundle isn't available. */
    share: ShareDialog | null;
    actorJson: string;
    onadd: () => void;
    onrename: (credential: Credential) => void;
    onrotate: (credential: Credential) => void;
    ondelete: (credential: Credential) => void;
    onsharechanged: () => void;
  } = $props();

  function scrollIntoView(node: HTMLElement, highlighted: boolean) {
    if (highlighted)
      node.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
</script>

<section>
  <div class="heading">
    <h2>Service accounts</h2>
    {#if canAdd}
      <button type="button" class="button" onclick={onadd}
        >Add service account</button
      >
    {/if}
  </div>

  {#if accounts.length === 0}
    <p class="empty">
      {canAdd
        ? "No service accounts yet. Add one with its JSON key, then share spreadsheets with its email address."
        : "No service accounts are shared with you."}
    </p>
  {:else}
    <ul class="cards">
      {#each accounts as account (account.id)}
        <li
          class="card"
          class:highlight={account.id === highlightId}
          use:scrollIntoView={account.id === highlightId}
        >
          <div class="title">
            <strong>{account.label}</strong>
            {#if account.role}<span class="badge">{account.role}</span>{/if}
            {#if account.status === "broken"}
              <span class="badge badge-broken">Broken</span>
            {/if}
          </div>

          {#if account.google_email}
            <div class="share-with">
              <code class="client-email">{account.google_email}</code>
              <CopyButton text={account.google_email} />
              <p class="small">Share your spreadsheet with this address.</p>
            </div>
          {/if}

          {#if account.status === "broken"}
            <p class="problem">
              {account.status_detail ?? "Google stopped accepting this key."}
            </p>
          {/if}

          <dl>
            <dt>Last used</dt>
            <dd>{formatTimestamp(account.last_used_at)}</dd>
          </dl>

          <div class="actions">
            {#if account.can_edit}
              <button type="button" onclick={() => onrename(account)}
                >Rename</button
              >
              <button type="button" onclick={() => onrotate(account)}
                >Rotate key</button
              >
            {/if}
            {#if account.can_manage && share}
              <datasette-acl-share-dialog
                resource-type="google-service-account"
                parent={account.id}
                resource-label={account.label}
                actor-json={actorJson}
                features={share.features}
                trigger-label="Share"
                onshare-changed={onsharechanged}
              ></datasette-acl-share-dialog>
            {/if}
            {#if account.can_manage}
              <button type="button" onclick={() => ondelete(account)}
                >Delete</button
              >
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .highlight {
    outline: 3px solid #d4a72c;
    background: #fffdf0;
  }
  .share-with {
    margin: 0.5rem 0;
  }
  .client-email {
    font-size: 1.05rem;
    font-weight: bold;
    word-break: break-all;
  }
  .share-with .small {
    margin: 0.2rem 0 0;
  }
</style>
