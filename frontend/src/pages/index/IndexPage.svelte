<script lang="ts">
  import type { IndexPageData } from "../../page_data/IndexPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";

  // Placeholder: the management page arrives with ticket 14.
  const pageData = loadPageData<IndexPageData>();
  const status = $state(pageData.status);
</script>

<h1>Google accounts</h1>

<p>The management page is not built yet.</p>

{#if !status.encryption_configured}
  <p>No <code>encryption-key</code> is configured.</p>
{/if}
