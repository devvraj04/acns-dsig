/**
 * Client-side UX & Validation for Document Verification
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 */
document.addEventListener("DOMContentLoaded", () => {
    const verifyForm = document.getElementById("verifyForm");
    const docInput = document.getElementById("document");
    const envInput = document.getElementById("envelope");
    const docDropzone = document.getElementById("docDropzone");
    const envDropzone = document.getElementById("envDropzone");
    const docSelectedBox = document.getElementById("docSelectedBox");
    const envSelectedBox = document.getElementById("envSelectedBox");
    const docSelectedName = document.getElementById("docSelectedName");
    const envSelectedName = document.getElementById("envSelectedName");
    const docSelectedSize = document.getElementById("docSelectedSize");
    const envSelectedSize = document.getElementById("envSelectedSize");
    const removeDocBtn = document.getElementById("removeDocBtn");
    const removeEnvBtn = document.getElementById("removeEnvBtn");
    const verifySubmitBtn = document.getElementById("verifySubmitBtn");
    const verifyClientAlert = document.getElementById("verifyClientAlert");

    const MAX_DOC_BYTES = 50 * 1024 * 1024; // 50 MB
    const MAX_ENV_BYTES = 512 * 1024;       // 512 KB

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function showClientError(msg) {
        if (!verifyClientAlert) return;
        verifyClientAlert.textContent = msg;
        verifyClientAlert.style.display = "block";
    }

    function clearClientError() {
        if (!verifyClientAlert) return;
        verifyClientAlert.textContent = "";
        verifyClientAlert.style.display = "none";
    }

    // Setup Dropzone handlers
    function setupDropzone(dropzone, input, box, nameEl, sizeEl, maxBytes, isEnvelope) {
        if (!dropzone || !input) return;

        dropzone.addEventListener("click", () => input.click());

        ["dragenter", "dragover"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove("dragover");
            });
        });

        dropzone.addEventListener("drop", (e) => {
            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                handleFileSelect(input.files[0], dropzone, box, nameEl, sizeEl, maxBytes, isEnvelope);
            }
        });

        input.addEventListener("change", () => {
            if (input.files.length > 0) {
                handleFileSelect(input.files[0], dropzone, box, nameEl, sizeEl, maxBytes, isEnvelope);
            }
        });
    }

    function handleFileSelect(file, dropzone, box, nameEl, sizeEl, maxBytes, isEnvelope) {
        clearClientError();
        if (!file) return;

        if (file.size > maxBytes) {
            showClientError(`File "${file.name}" exceeds maximum allowed limit (${formatBytes(maxBytes)}).`);
        }

        if (isEnvelope && !file.name.toLowerCase().endsWith(".json")) {
            showClientError(`Notice: Signature envelope "${file.name}" should end with .dsig.json or .json`);
        }

        nameEl.textContent = file.name;
        sizeEl.textContent = formatBytes(file.size);
        box.style.display = "flex";
        dropzone.style.display = "none";
    }

    setupDropzone(docDropzone, docInput, docSelectedBox, docSelectedName, docSelectedSize, MAX_DOC_BYTES, false);
    setupDropzone(envDropzone, envInput, envSelectedBox, envSelectedName, envSelectedSize, MAX_ENV_BYTES, true);

    if (removeDocBtn && docInput && docDropzone && docSelectedBox) {
        removeDocBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            docInput.value = "";
            docSelectedBox.style.display = "none";
            docDropzone.style.display = "flex";
            clearClientError();
        });
    }

    if (removeEnvBtn && envInput && envDropzone && envSelectedBox) {
        removeEnvBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            envInput.value = "";
            envSelectedBox.style.display = "none";
            envDropzone.style.display = "flex";
            clearClientError();
        });
    }

    if (verifyForm) {
        verifyForm.addEventListener("submit", (e) => {
            clearClientError();

            if (!docInput.files || docInput.files.length === 0) {
                e.preventDefault();
                showClientError("Please select the received document file to verify.");
                return;
            }

            if (!envInput.files || envInput.files.length === 0) {
                e.preventDefault();
                showClientError("Please select the .dsig.json signature envelope file.");
                return;
            }

            const docFile = docInput.files[0];
            const envFile = envInput.files[0];

            if (docFile.size > MAX_DOC_BYTES) {
                e.preventDefault();
                showClientError(`Document size (${formatBytes(docFile.size)}) exceeds the 50 MB limit.`);
                return;
            }

            if (envFile.size > MAX_ENV_BYTES) {
                e.preventDefault();
                showClientError(`Signature envelope size (${formatBytes(envFile.size)}) exceeds 512 KB.`);
                return;
            }

            // Spinner / submitting state
            if (verifySubmitBtn) {
                verifySubmitBtn.disabled = true;
                verifySubmitBtn.innerHTML = `
                    <svg class="spin-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite; vertical-align: middle; margin-right: 0.5rem;">
                        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
                        <path d="M12 2a10 10 0 0 1 10 10"></path>
                    </svg>
                    Verifying Cryptographic Authenticity &amp; Integrity...
                `;
            }
        });
    }
});
