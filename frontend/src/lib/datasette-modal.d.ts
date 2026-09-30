/**
 * Types for Datasette's `DatasetteModal` (core `static/modal.js`, 1.0a41+),
 * loaded by `base.html` on every page. Use it for dialogs instead of a
 * custom modal. See `docs/javascript_plugins.rst` "Reusable modal dialogs".
 */

type DatasetteModalCloseSource = "cancel" | "escape" | "backdrop" | string;

interface DatasetteModalElement extends HTMLElement {
  readonly dialog: HTMLDialogElement;
  /** While true, user dismissal (`requestClose`) is refused. */
  busy: boolean;
  /** Return false to keep the dialog open. */
  beforeClose: ((source: DatasetteModalCloseSource) => boolean) | null;
  show(options?: {
    returnFocusTo?: HTMLElement;
    initialFocus?: HTMLElement | (() => void);
  }): void;
  requestClose(source?: DatasetteModalCloseSource): boolean;
  close(options?: { restoreFocus?: boolean }): void;
}

declare var DatasetteModal: {
  /** A detached `<datasette-modal>` wrapping a native `<dialog>`. */
  create(): DatasetteModalElement;
};
