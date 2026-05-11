window.__rusthostStressSuite = {
  ready: true,
  title: "RustHost Stress Suite",
  loadedAt: new Date().toISOString(),
};

document.addEventListener("DOMContentLoaded", () => {
  const status = document.querySelector("#status");
  if (status) {
    status.textContent = "The fixture script loaded successfully.";
  }
});
