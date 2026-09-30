import { mount } from "svelte";
import IndexPage from "./IndexPage.svelte";
import "./page.css";

const app = mount(IndexPage, {
  target: document.getElementById("app-root")!,
});

export default app;
