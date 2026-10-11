/**
 * Client-side Filtering & Search for Verification History
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 */
document.addEventListener("DOMContentLoaded", () => {
    const filterPills = document.querySelectorAll(".filter-pill");
    const searchInput = document.getElementById("historySearchInput");
    const historyRows = document.querySelectorAll(".history-row");
    const noHistoryMatch = document.getElementById("noHistoryMatch");

    let currentFilter = "ALL";
    let searchQuery = "";

    function applyFilters() {
        let visibleCount = 0;

        historyRows.forEach(row => {
            const rowResult = (row.getAttribute("data-result") || "").toUpperCase();
            const docName = (row.getAttribute("data-doc") || "").toLowerCase();
            const keyId = (row.getAttribute("data-key") || "").toLowerCase();

            // Status category match
            let matchesStatus = false;
            if (currentFilter === "ALL") {
                matchesStatus = true;
            } else if (currentFilter === "VALID_TRUSTED") {
                matchesStatus = (rowResult === "VALID_TRUSTED");
            } else if (currentFilter === "VALID_UNTRUSTED_SIGNER") {
                matchesStatus = (rowResult === "VALID_UNTRUSTED_SIGNER");
            } else if (currentFilter === "DOCUMENT_TAMPERED") {
                matchesStatus = (rowResult === "DOCUMENT_TAMPERED");
            } else if (currentFilter === "OTHER") {
                matchesStatus = (rowResult !== "VALID_TRUSTED" && rowResult !== "VALID_UNTRUSTED_SIGNER" && rowResult !== "DOCUMENT_TAMPERED");
            }

            // Keyword match
            let matchesSearch = true;
            if (searchQuery) {
                matchesSearch = docName.includes(searchQuery) || keyId.includes(searchQuery);
            }

            if (matchesStatus && matchesSearch) {
                row.style.display = "";
                visibleCount++;
            } else {
                row.style.display = "none";
            }
        });

        if (noHistoryMatch) {
            noHistoryMatch.style.display = (visibleCount === 0) ? "" : "none";
        }
    }

    filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
            filterPills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            currentFilter = pill.getAttribute("data-filter") || "ALL";
            applyFilters();
        });
    });

    if (searchInput) {
        searchInput.addEventListener("input", () => {
            searchQuery = searchInput.value.toLowerCase().trim();
            applyFilters();
        });
    }

    // Copy to clipboard helpers
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
