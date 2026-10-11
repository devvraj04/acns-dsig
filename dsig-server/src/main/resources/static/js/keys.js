/**
 * keys.js — client-side logic for the key management screen.
 *
 * Responsibilities:
 *   - Passphrase strength indicator
 *   - Passphrase confirmation matching (real-time)
 *   - Key generation form validation with accessible error messages
 *   - Copy-to-clipboard for fingerprints
 *   - Password visibility toggle
 *   - Retire confirmation dialog
 */

"use strict";

// ── DOM ready ────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    initPassphraseStrength();
    initPassphraseConfirmation();
    initKeygenFormValidation();
});

// ── Passphrase strength indicator ─────────────────────────────────────────────

function initPassphraseStrength() {
    const input = document.getElementById("passphrase");
    const bar = document.getElementById("strengthBar");
    const container = document.getElementById("passphraseStrength");
    if (!input || !bar || !container) return;

    input.addEventListener("input", () => {
        const score = measureStrength(input.value);
        container.setAttribute("aria-valuenow", String(score));
        bar.style.width = (score / 4 * 100) + "%";
        bar.className = "strength-bar strength-" + ["empty","weak","fair","good","strong"][score];
        const labels = ["", "Weak", "Fair", "Good", "Strong"];
        container.setAttribute("aria-label", "Passphrase strength: " + (labels[score] || ""));
    });
}

/**
 * Returns a strength score 0–4 based on simple heuristics.
 */
function measureStrength(pwd) {
    if (!pwd) return 0;
    let score = 0;
    if (pwd.length >= 8)  score++;
    if (pwd.length >= 14) score++;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd) && /[^A-Za-z0-9]/.test(pwd)) score++;
    return score;
}

// ── Passphrase confirmation matching ──────────────────────────────────────────

function initPassphraseConfirmation() {
    const pwd = document.getElementById("passphrase");
    const confirm = document.getElementById("passphraseConfirm");
    const hint = document.getElementById("confirmHint");
    if (!pwd || !confirm || !hint) return;

    function check() {
        if (confirm.value.length === 0) {
            hint.textContent = "";
            confirm.removeAttribute("aria-invalid");
            return;
        }
        if (pwd.value === confirm.value) {
            hint.textContent = "✓ Passphrases match.";
            hint.style.color = "var(--success)";
            confirm.setAttribute("aria-invalid", "false");
        } else {
            hint.textContent = "✗ Passphrases do not match.";
            hint.style.color = "var(--danger)";
            confirm.setAttribute("aria-invalid", "true");
        }
    }

    confirm.addEventListener("input", check);
    pwd.addEventListener("input", check);
}

// ── Key generation form validation ────────────────────────────────────────────

function initKeygenFormValidation() {
    const form = document.getElementById("keygenForm");
    const errBox = document.getElementById("keygenError");
    if (!form || !errBox) return;

    form.addEventListener("submit", (e) => {
        const label = document.getElementById("label");
        const pwd = document.getElementById("passphrase");
        const confirm = document.getElementById("passphraseConfirm");

        // Clear previous errors
        showError(errBox, null);

        if (!label || label.value.trim().length === 0) {
            e.preventDefault();
            showError(errBox, "Key label is required.");
            label && label.focus();
            return;
        }
        if (!pwd || pwd.value.length < 8) {
            e.preventDefault();
            showError(errBox, "Passphrase must be at least 8 characters.");
            pwd && pwd.focus();
            return;
        }
        if (!confirm || pwd.value !== confirm.value) {
            e.preventDefault();
            showError(errBox, "Passphrases do not match. Please re-enter both passphrase fields.");
            confirm && confirm.focus();
            return;
        }

        // Disable button to prevent double-submit
        const btn = document.getElementById("keygenSubmit");
        if (btn) {
            btn.disabled = true;
            btn.textContent = "Generating key pair… this may take a few seconds";
        }
    });
}

// ── Utility: show accessible inline error ─────────────────────────────────────

function showError(container, message) {
    if (!container) return;
    if (message) {
        container.textContent = message;
        container.style.display = "block";
        container.focus();
    } else {
        container.style.display = "none";
        container.textContent = "";
    }
}

// ── Copy fingerprint to clipboard ─────────────────────────────────────────────

function copyFromButton(btn) {
    if (!btn) return;
    const text = btn.getAttribute("data-copy") || "";
    copyToClipboard(text, btn);
}

/**
 * Copies text to clipboard, providing visual and accessible feedback on the triggering button.
 *
 * @param {string} text - The text to copy.
 * @param {HTMLElement} btn - The button element to update with feedback.
 */
function copyToClipboard(text, btn) {
    if (!navigator.clipboard) {
        // Fallback for browsers without clipboard API
        const el = document.createElement("textarea");
        el.value = text;
        el.style.position = "fixed";
        el.style.top = "-9999px";
        document.body.appendChild(el);
        el.select();
        document.execCommand("copy");
        document.body.removeChild(el);
        feedbackCopied(btn);
        return;
    }
    navigator.clipboard.writeText(text).then(() => feedbackCopied(btn)).catch(() => {
        if (btn) btn.textContent = "Copy failed";
    });
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
 * Toggles between password/text on a password input.
 *
 * @param {string} inputId - The ID of the password input element.
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

// ── Retire key confirmation ────────────────────────────────────────────────────

/**
 * Shows a confirmation dialog before retiring a key.
 * Returns false to cancel the form submission if the user declines.
 *
 * @param {Event} e - The form submit event.
 * @returns {boolean}
 */
function confirmRetire(e) {
    const ok = window.confirm(
        "Are you sure you want to RETIRE this key?\n\n" +
        "Once retired:\n" +
        "• The key cannot be used for new signing operations.\n" +
        "• Existing signatures may still be mathematically verifiable.\n\n" +
        "This action cannot be undone without administrator access."
    );
    if (!ok) {
        e.preventDefault();
        return false;
    }
    return true;
}
