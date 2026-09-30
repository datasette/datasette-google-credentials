import { mount } from "svelte";
import AdminPage from "./AdminPage.svelte";
import "../../lib/page.css";

const app = mount(AdminPage, {
  target: document.getElementById("app-root")!,
});

export default app;
