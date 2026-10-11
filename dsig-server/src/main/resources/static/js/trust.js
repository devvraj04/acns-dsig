/**
 * Client-side UX & Validation for Trust Store
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Fingerprint input cleaner & counter
    const fpInput = document.getElementById("fingerprint");
    const fpCounter = document.getElementById("fpCounter");
    const pinForm = document.getElementById("pinTrustForm");
    const pinError = document.getElementById("pinClientError");

    if (fpInput && fpCounter) {
        function updateFpStatus() {
            // Strip any extraneous colons, spaces, or dashes
            const raw = fpInput.value;
            const cleaned = raw.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
            if (raw !== cleaned && !raw.includes(":") && !raw.includes(" ")) {
                // Keep input updated with cleaned value if user pasted with symbols
                fpInput.value = cleaned;
            }

            const len = cleaned.length;
            fpCounter.textContent = `${len}/64 hex characters`;

            if (len === 64) {
                fpCounter.style.color = "var(--success)";
            } else if (len > 64) {
                fpCounter.style.color = "var(--danger)";
            } else {
                fpCounter.style.color = "var(--text-muted)";
            }
        }

        fpInput.addEventListener("input", updateFpStatus);
        updateFpStatus();
    }

    if (pinForm) {
        pinForm.addEventListener("submit", (e) => {
            const raw = fpInput.value.trim();
            const cleaned = raw.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
            const labelInput = document.getElementById("label");

            if (pinError) pinError.style.display = "none";

            if (!labelInput || !labelInput.value.trim()) {
                e.preventDefault();
                if (pinError) {
                    pinError.textContent = "Please provide a friendly label or organization for the signer.";
                    pinError.style.display = "block";
                }
                return;
            }

            if (cleaned.length !== 64) {
                e.preventDefault();
                if (pinError) {
                    pinError.textContent = `A valid SHA-256 fingerprint must be exactly 64 hexadecimal characters. (Currently: ${cleaned.length})`;
                    pinError.style.display = "block";
                }
                return;
            }

            // Normalise value before submission
            fpInput.value = cleaned;
        });
    }

    // 2. Revoke confirmation dialog
    document.querySelectorAll(".revoke-form").forEach(form => {
        form.addEventListener("submit", (e) => {
            const signerLabel = form.getAttribute("data-label") || "this signer";
            const confirmed = window.confirm(`Are you sure you want to REVOKE trust for "${signerLabel}"?\nAny future documents signed by this key will no longer be considered trusted.`);
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });

    // 3. Instant search / filter for signers table
    const searchInput = document.getElementById("trustSearchInput");
    const signerRows = document.querySelectorAll(".signer-row");
    const noResultsRow = document.getElementById("noSignersMatch");

    if (searchInput && signerRows.length > 0) {
        searchInput.addEventListener("input", () => {
            const query = searchInput.value.toLowerCase().trim();
            let visibleCount = 0;

            signerRows.forEach(row => {
                const label = (row.getAttribute("data-label") || "").toLowerCase();
                const fp = (row.getAttribute("data-fp") || "").toLowerCase();
                const note = (row.getAttribute("data-note") || "").toLowerCase();

                if (label.includes(query) || fp.includes(query) || note.includes(query)) {
                    row.style.display = "";
                    visibleCount++;
                } else {
                    row.style.display = "none";
                }
            });

            if (noResultsRow) {
                noResultsRow.style.display = (visibleCount === 0) ? "" : "none";
            }
        });
    }

    // 4. Copy to clipboard for table fingerprints
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const textToCopy = btn.getAttribute("data-copy") || "";
            if (!textToCopy) return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = `<span style="color:var(--success);">✓ Copied</span>`;
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                }, 2000);
            });
        });
    });
});
