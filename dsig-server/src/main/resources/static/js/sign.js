/**
 * sign.js — client-side logic for the document signing screen.
 *
 * Responsibilities:
 *   - Client-side file validation (empty file, size > 50 MB)
 *   - Real-time file info preview (name + size)
 *   - Key selection fingerprint preview
 *   - Passphrase visibility toggle
 *   - Submit button loading state + spinner
 *   - Accessible error messages
 *   - Clipboard copy for hash/fingerprint values
 *   - Passive copy-to-clipboard utility (shared with keys.js)
 */

"use strict";

// Maximum upload size enforced server-side (50 MB = 52 428 800 bytes).
// The client-side check is a UX guard only — the server enforces the actual limit.
const MAX_FILE_BYTES = 52_428_800;

// ── DOM ready ────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    initFileInfoPreview();
    initKeyFingerprintPreview();
    initSignFormValidation();
});

// ── File info preview ─────────────────────────────────────────────────────────

function initFileInfoPreview() {
    const fileInput = document.getElementById("document");
    const fileInfoBox = document.getElementById("fileInfo");
    const fileNameEl = document.getElementById("fileName");
    const fileSizeEl = document.getElementById("fileSize");
    const sizeWarning = document.getElementById("fileSizeWarning");

    if (!fileInput) return;

    fileInput.addEventListener("change", () => {
        if (!fileInput.files || fileInput.files.length === 0) {
            if (fileInfoBox) fileInfoBox.style.display = "none";
            return;
        }

        const file = fileInput.files[0];
        if (fileInfoBox) fileInfoBox.style.display = "block";
        if (fileNameEl) fileNameEl.textContent = file.name;
        if (fileSizeEl) fileSizeEl.textContent = "(" + formatBytes(file.size) + ")";

        // Warn but don't block yet — let the validation on submit handle it
        if (sizeWarning) {
            if (file.size > MAX_FILE_BYTES) {
                sizeWarning.textContent = "⚠ File exceeds 50 MB limit. Signing will be rejected.";
                sizeWarning.style.display = "inline";
                fileInput.setAttribute("aria-invalid", "true");
            } else if (file.size === 0) {
                sizeWarning.textContent = "⚠ Empty files (0 bytes) cannot be signed.";
                sizeWarning.style.display = "inline";
                fileInput.setAttribute("aria-invalid", "true");
            } else {
                sizeWarning.style.display = "none";
                fileInput.removeAttribute("aria-invalid");
            }
        }
    });
}

// ── Key selection fingerprint preview ─────────────────────────────────────────

function initKeyFingerprintPreview() {
    const select = document.getElementById("keyId");
    const fpContainer = document.getElementById("selectedFingerprint");
    const fpValue = document.getElementById("fingerprintValue");

    if (!select || !fpContainer || !fpValue) return;

    select.addEventListener("change", () => {
        const selected = select.options[select.selectedIndex];
        const fingerprint = selected ? selected.getAttribute("data-fingerprint") : null;
        if (fingerprint) {
            fpValue.textContent = fingerprint;
            fpContainer.style.display = "block";
        } else {
            fpContainer.style.display = "none";
        }
    });
}

// ── Sign form validation ───────────────────────────────────────────────────────

function initSignFormValidation() {
    const form = document.getElementById("signForm");
    const errBox = document.getElementById("signError");
    const submitBtn = document.getElementById("signSubmitBtn");
    const btnText = document.getElementById("btnText");
    const btnSpinner = document.getElementById("btnSpinner");

    if (!form) return;

    form.addEventListener("submit", (e) => {
        // Clear previous error
        showError(errBox, null);

        const fileInput = document.getElementById("document");
        const keySelect = document.getElementById("keyId");
        const passInput = document.getElementById("passphrase");

        // 1. File required
        if (!fileInput || fileInput.files.length === 0) {
            e.preventDefault();
            showError(errBox, "Please select a document to sign.");
            fileInput && fileInput.focus();
            return;
        }

        const file = fileInput.files[0];

        // 2. Empty file check
        if (file.size === 0) {
            e.preventDefault();
            showError(errBox, "The selected file is empty (0 bytes). Only non-empty files can be signed.");
            fileInput.focus();
            return;
        }

        // 3. File size limit
        if (file.size > MAX_FILE_BYTES) {
            e.preventDefault();
            showError(errBox,
                "The selected file (" + formatBytes(file.size) + ") exceeds the 50 MB maximum. " +
                "Please choose a smaller file."
            );
            fileInput.focus();
            return;
        }

        // 4. Key selected
        if (!keySelect || !keySelect.value) {
            e.preventDefault();
            showError(errBox, "Please select a signing key from the dropdown.");
            keySelect && keySelect.focus();
            return;
        }

        // 5. Passphrase required
        if (!passInput || passInput.value.trim().length === 0) {
            e.preventDefault();
            showError(errBox, "Please enter your private key passphrase.");
            passInput && passInput.focus();
            return;
        }

        // All validations passed — show loading state
        if (submitBtn) submitBtn.disabled = true;
        if (btnText)    btnText.style.display = "none";
        if (btnSpinner) btnSpinner.style.display = "inline";
    });
}

// ── Utility: show accessible inline error ─────────────────────────────────────

function showError(container, message) {
    if (!container) return;
    if (message) {
        container.textContent = message;
        container.style.display = "block";
        container.scrollIntoView({ behavior: "smooth", block: "nearest" });
        container.focus();
    } else {
        container.style.display = "none";
        container.textContent = "";
    }
}

// ── Utility: human-readable file size ─────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + " " + units[i];
}

// ── Copy to clipboard (shared with result panel) ───────────────────────────────

function copyFromButton(btn) {
    if (!btn) return;
    const text = btn.getAttribute("data-copy") || "";
    copyToClipboard(text, btn);
}

/**
 * Copies text to clipboard with visual feedback on the triggering button.
 *
 * @param {string} text - The text to copy.
 * @param {HTMLElement} btn - The button element providing feedback.
 */
function copyToClipboard(text, btn) {
    const doFallback = () => {
        const el = document.createElement("textarea");
        el.value = text;
        el.style.position = "fixed";
        el.style.top = "-9999px";
        document.body.appendChild(el);
        el.select();
        document.execCommand("copy");
        document.body.removeChild(el);
        feedbackCopied(btn);
    };

    if (!navigator.clipboard) {
        doFallback();
        return;
    }
    navigator.clipboard.writeText(text).then(() => feedbackCopied(btn)).catch(doFallback);
}

function feedbackCopied(btn) {
    if (!btn) return;
    const original = btn.textContent;
    btn.textContent = "Copied!";
    btn.setAttribute("aria-label", "Copied to clipboard");
    setTimeout(() => {
        btn.textContent = original;
        btn.removeAttribute("aria-label");
    }, 2000);
}

// ── Password visibility toggle ────────────────────────────────────────────────

/**
 * Toggles between password and text mode on a password input.
 *
 * @param {string} inputId - ID of the password input element.
 * @param {HTMLElement} btn - The toggle button element.
 */
function toggleVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "\u{1F648}" : "\u{1F441}";
    btn.setAttribute("aria-label", isHidden ? "Hide passphrase" : "Show passphrase");
}
