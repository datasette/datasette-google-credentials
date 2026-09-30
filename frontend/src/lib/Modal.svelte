<script lang="ts">
  import type { Snippet } from "svelte";

  /**
   * A dialog on core's `DatasetteModal` (shared styles, Escape/backdrop
   * dismissal, busy guard, focus return). The `<datasette-modal>` wrapper is
   * rendered in place rather than via `DatasetteModal.create()`: same
   * element, and Svelte keeps owning the content. `showModal()` puts it in
   * the top layer, so where it sits in the DOM doesn't matter.
   */
  let {
    open,
    title,
    busy = false,
    onclose,
    children,
    footer,
  }: {
    open: boolean;
    title: string;
    /** While true, Escape/backdrop/Cancel can't close it (a request is running). */
    busy?: boolean;
    /** Called once the dialog has closed, however it was closed. */
    onclose: () => void;
    children: Snippet;
    footer: Snippet<[{ requestClose: () => void }]>;
  } = $props();

  const titleId = `google-auth-modal-${Math.random().toString(36).slice(2)}`;
  let wrapper = $state<DatasetteModalElement>();

  $effect(() => {
    const modal = wrapper;
    if (!modal) return;
    if (open && !modal.dialog.open) {
      modal.show();
    } else if (!open && modal.dialog.open) {
      modal.close();
    }
  });

  $effect(() => {
    if (wrapper) wrapper.busy = busy;
  });

  function requestClose() {
    wrapper?.requestClose("cancel");
  }
</script>

<datasette-modal bind:this={wrapper}>
  <dialog
    aria-labelledby={titleId}
    onclose={(event) => {
      if (event.target === event.currentTarget) onclose();
    }}
  >
    <div class="modal-header">
      <h2 class="modal-title" id={titleId}>{title}</h2>
    </div>
    <div class="modal-body">
      {@render children()}
    </div>
    <div class="modal-footer">
      {@render footer({ requestClose })}
    </div>
  </dialog>
</datasette-modal>

<style>
  dialog {
    width: min(640px, calc(100vw - 32px));
  }
</style>
