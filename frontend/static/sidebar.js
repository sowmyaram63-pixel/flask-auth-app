
document.addEventListener("DOMContentLoaded", () => {
    const primary = document.querySelector(".primary-sidebar");
    const secondary = document.querySelector(".secondary-sidebar");

    // Ensures they don't overlap
    secondary.style.marginLeft = primary.offsetWidth + "px";
});
