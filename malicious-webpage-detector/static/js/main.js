/**
 * Malicious Webpage Behavior Detection System - Frontend JavaScript
 */

let currentScanId = null;

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("analyze-form");
    const urlInput = document.getElementById("url-input");
    const analyzeBtn = document.getElementById("analyze-btn");
    const btnText = analyzeBtn.querySelector(".btn-text");
    const btnLoading = analyzeBtn.querySelector(".btn-loading");
    const resultsSection = document.getElementById("results-section");
    const errorMessage = document.getElementById("error-message");
    const resultsContent = document.getElementById("results-content");
    const riskBadge = document.getElementById("risk-badge");
    const riskLevel = document.getElementById("risk-level");
    const scoreFill = document.getElementById("score-fill");
    const scoreText = document.getElementById("score-text");
    const findingsList = document.getElementById("findings-list");
    const recommendationsList = document.getElementById("recommendations-list");
    const exportJsonBtn = document.getElementById("export-json-btn");
    const exportPdfBtn = document.getElementById("export-pdf-btn");
    const clearHistoryBtn = document.getElementById("clear-history-btn");
    const historyList = document.getElementById("history-list");

    // Load history on page load
    loadHistory();

    // Form submission handler
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        // Show loading state
        setLoading(true);
        hideResults();

        try {
            const response = await fetch("/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (!response.ok) {
                showError(data.error || "An error occurred while analyzing");
                return;
            }

            displayResults(data);
        } catch (error) {
            showError("Failed to connect to the server. Please try again.");
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        if (isLoading) {
            analyzeBtn.disabled = true;
            btnText.style.display = "none";
            btnLoading.style.display = "inline-flex";
        } else {
            analyzeBtn.disabled = false;
            btnText.style.display = "inline";
            btnLoading.style.display = "none";
        }
    }

    function hideResults() {
        resultsSection.style.display = "block";
        errorMessage.style.display = "none";
        resultsContent.style.display = "none";
    }

    function showError(message) {
        resultsSection.style.display = "block";
        errorMessage.style.display = "block";
        errorMessage.textContent = message;
        resultsContent.style.display = "none";
    }

    function displayResults(data) {
        resultsSection.style.display = "block";
        errorMessage.style.display = "none";
        resultsContent.style.display = "block";

        // Update risk level
        riskLevel.textContent = data.risk_level;
        riskBadge.className = "risk-badge " + data.risk_level.toLowerCase();

        // Update score bar
        const score = data.risk_score;
        scoreFill.style.width = score + "%";
        scoreText.textContent = score + "/100";

        // Set score bar color based on risk level
        const colors = {
            LOW: "var(--color-low)",
            MEDIUM: "var(--color-medium)",
            HIGH: "var(--color-high)",
            CRITICAL: "var(--color-critical)",
        };
        scoreFill.style.backgroundColor = colors[data.risk_level] || colors.LOW;

        // Update findings
        findingsList.innerHTML = "";
        if (data.findings && data.findings.length > 0) {
            data.findings.forEach((finding) => {
                const findingEl = document.createElement("div");
                findingEl.className = "finding-item " + finding.severity.toLowerCase();
                findingEl.innerHTML = `
                    <span class="finding-category">${finding.category}</span>
                    <p class="finding-description">${finding.description}</p>
                    <code class="finding-evidence">${escapeHtml(finding.evidence)}</code>
                `;
                findingsList.appendChild(findingEl);
            });
        } else {
            findingsList.innerHTML = "<p>No suspicious behavior detected.</p>";
        }

        // Update recommendations
        recommendationsList.innerHTML = "";
        if (data.recommendations && data.recommendations.length > 0) {
            data.recommendations.forEach((rec) => {
                const li = document.createElement("li");
                li.textContent = rec;
                if (data.risk_level === "LOW") {
                    li.classList.add("safe");
                }
                recommendationsList.appendChild(li);
            });
        }

        // Show export buttons
        exportJsonBtn.style.display = "inline-block";
        exportPdfBtn.style.display = "inline-block";

        // Get the latest scan ID from history
        loadHistory().then(() => {
            if (historyList.children.length > 0) {
                const firstItem = historyList.querySelector(".history-item");
                if (firstItem) {
                    currentScanId = firstItem.dataset.id;
                }
            }
        });
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    // Export JSON
    exportJsonBtn.addEventListener("click", () => {
        if (currentScanId) {
            window.location.href = `/export/${currentScanId}`;
        }
    });

    // Export PDF (simple print)
    exportPdfBtn.addEventListener("click", () => {
        window.print();
    });

    // Clear history
    clearHistoryBtn.addEventListener("click", async () => {
        if (confirm("Are you sure you want to clear all scan history?")) {
            await fetch("/history/clear", { method: "POST" });
            loadHistory();
        }
    });

    // Load history
    async function loadHistory() {
        try {
            const response = await fetch("/history");
            const history = await response.json();

            historyList.innerHTML = "";

            if (history.length === 0) {
                historyList.innerHTML = '<p class="empty-message">No scan history yet.</p>';
                return;
            }

            history.forEach((item) => {
                const itemEl = document.createElement("div");
                itemEl.className = "history-item";
                itemEl.dataset.id = item.id;
                itemEl.innerHTML = `
                    <div class="history-item-info">
                        <span class="history-item-url">${escapeHtml(item.url)}</span>
                        <div class="history-item-meta">
                            <span class="history-item-score">${item.risk_score}/100</span>
                            <span class="history-item-badge ${item.risk_level.toLowerCase()}">${item.risk_level}</span>
                        </div>
                    </div>
                    <button class="history-item-delete" data-id="${item.id}">✕</button>
                `;

                // Click to view details
                itemEl.addEventListener("click", (e) => {
                    if (e.target.classList.contains("history-item-delete")) return;
                    loadScanDetail(item.id);
                });

                // Delete button
                itemEl.querySelector(".history-item-delete").addEventListener("click", async (e) => {
                    e.stopPropagation();
                    await fetch(`/history/${item.id}`, { method: "DELETE" });
                    loadHistory();
                });

                historyList.appendChild(itemEl);
            });
        } catch (error) {
            console.error("Failed to load history:", error);
        }
    }

    // Load scan detail
    async function loadScanDetail(scanId) {
        try {
            const response = await fetch(`/history/${scanId}`);
            const data = await response.json();

            if (data.error) {
                showError(data.error);
                return;
            }

            currentScanId = scanId;
            displayResults(data);
        } catch (error) {
            showError("Failed to load scan details.");
        }
    }
});
