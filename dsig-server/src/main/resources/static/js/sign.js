// Client-side UX enhancements for document signing
document.addEventListener("DOMContentLoaded", () => {
    const signForm = document.getElementById("signForm");
    if (signForm) {
        signForm.addEventListener("submit", (e) => {
            const docInput = document.getElementById("document");
            if (docInput && docInput.files.length > 0) {
                const file = docInput.files[0];
                if (file.size === 0) {
                    alert("Error: Empty files (0 bytes) cannot be signed.");
                    e.preventDefault();
                    return;
                }
            }
        });
    }
});
