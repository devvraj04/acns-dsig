/**
 * Client-side Tamper Diff Visualization & Clipboard Helpers
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Copy to clipboard helper
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const targetEl = document.getElementById(targetId);
            if (!targetEl) return;

            const textToCopy = targetEl.getAttribute("data-copy") || targetEl.textContent.trim();
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = btn.innerHTML;
                btn.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    Copied!
                `;
                btn.style.borderColor = "var(--success)";
                btn.style.color = "var(--success)";
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.borderColor = "";
                    btn.style.color = "";
                }, 2000);
            }).catch(err => {
                console.error("Failed to copy text: ", err);
            });
        });
    });

    // 2. Character-by-character Tamper Diff Highlighter
    const authenticHashEl = document.getElementById("authenticHashDisplay");
    const recomputedHashEl = document.getElementById("recomputedHashDisplay");
    const diffSummaryEl = document.getElementById("tamperDiffSummary");

    if (authenticHashEl && recomputedHashEl) {
        const authenticHash = authenticHashEl.getAttribute("data-raw-hash") || "";
        const recomputedHash = recomputedHashEl.getAttribute("data-raw-hash") || "";

        if (authenticHash && recomputedHash && authenticHash !== recomputedHash && authenticHash !== "N/A" && recomputedHash !== "N/A") {
            let authenticHtml = "";
            let recomputedHtml = "";
            let diffCount = 0;
            const maxLen = Math.max(authenticHash.length, recomputedHash.length);

            for (let i = 0; i < maxLen; i++) {
                const aChar = authenticHash[i] || "";
                const rChar = recomputedHash[i] || "";

                if (aChar === rChar) {
                    authenticHtml += `<span class="hash-char-match">${aChar}</span>`;
                    recomputedHtml += `<span class="hash-char-match">${rChar}</span>`;
                } else {
                    diffCount++;
                    authenticHtml += `<span class="hash-char-diff" title="Index ${i}: authentic character">${aChar}</span>`;
                    recomputedHtml += `<span class="hash-char-diff" title="Index ${i}: altered in recomputed">${rChar}</span>`;
                }
            }

            authenticHashEl.innerHTML = authenticHtml;
            recomputedHashEl.innerHTML = recomputedHtml;

            if (diffSummaryEl) {
                diffSummaryEl.innerHTML = `
                    <strong>Cryptographic Tamper Alert:</strong> 
                    Detected <strong>${diffCount}</strong> altered hexadecimal nibbles / character mismatches between the authentic signed manifest hash and the recomputed file hash.
                `;
                diffSummaryEl.style.display = "block";
            }
        }
    }
});
