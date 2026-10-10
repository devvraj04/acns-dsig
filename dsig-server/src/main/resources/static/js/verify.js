// Client-side UX enhancements for document verification
document.addEventListener("DOMContentLoaded", () => {
    const verifyForm = document.getElementById("verifyForm");
    if (verifyForm) {
        verifyForm.addEventListener("submit", (e) => {
            const envelopeInput = document.getElementById("envelope");
            if (envelopeInput && envelopeInput.files.length > 0) {
                const fileName = envelopeInput.files[0].name;
                if (!fileName.endsWith(".json")) {
                    alert("Warning: Envelope file is expected to be a .dsig.json file.");
                }
            }
        });
    }
});
