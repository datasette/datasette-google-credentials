<script lang="ts">
  let { text, label = "Copy" }: { text: string; label?: string } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // No clipboard access (http, old browser): leave it to select + copy.
      return;
    }
    copied = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = false), 1500);
  }
</script>

<button type="button" class="copy" onclick={copy} aria-label="{label}: {text}">
  {copied ? "Copied" : label}
</button>

<style>
  .copy {
    font-size: 0.8rem;
    padding: 0.1rem 0.5rem;
    margin-left: 0.4rem;
    cursor: pointer;
  }
</style>
