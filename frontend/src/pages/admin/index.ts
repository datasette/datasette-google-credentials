import { mount } from "svelte";
import AdminPage from "./AdminPage.svelte";

const app = mount(AdminPage, {
  target: document.getElementById("app-root")!,
});

export default app;
