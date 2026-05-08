/**
 * WebGuard - Malicious Webpage Behavior Detection System
 * Modern Frontend JavaScript
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
    const gaugeFill = document.getElementById("gauge-fill");
    const gaugeScore = document.getElementById("gauge-score");
    const riskDescription = document.getElementById("risk-description");
    const findingsList = document.getElementById("findings-list");
    const recommendationsList = document.getElementById("recommendations-list");
    const exportJsonBtn = document.getElementById("export-json-btn");
    const exportPdfBtn = document.getElementById("export-pdf-btn");
    const clearHistoryBtn = document.getElementById("clear-history-btn");
    const historyList = document.getElementById("history-list");

    // Summary counters
    const countIframe = document.getElementById("count-iframe");
    const countJs = document.getElementById("count-js");
    const countScripts = document.getElementById("count-scripts");
    const countLinks = document.getElementById("count-links");
    const countMining = document.getElementById("count-mining");

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
            btnText.style.display = "inline-flex";
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
        riskBadge.className = "risk-badge-large " + data.risk_level.toLowerCase();

        // Update gauge
        const score = data.risk_score;
        const circumference = 2 * Math.PI * 50; // r=50
        const offset = circumference - (score / 100) * circumference;
        gaugeFill.style.strokeDashoffset = offset;
        gaugeScore.textContent = score;

        // Set gauge color based on risk level
        const colors = {
            LOW: "var(--color-low)",
            MEDIUM: "var(--color-medium)",
            HIGH: "var(--color-high)",
            CRITICAL: "var(--color-critical)",
        };
        gaugeFill.style.stroke = colors[data.risk_level] || colors.LOW;

        // Update risk description
        const descriptions = {
            LOW: "This website appears to be safe. No significant threats detected.",
            MEDIUM: "Some suspicious behavior detected. Exercise caution when using this site.",
            HIGH: "Multiple threats detected. Avoid entering personal information on this site.",
            CRITICAL: "Severe threats detected! Avoid this website completely.",
        };
        riskDescription.textContent = descriptions[data.risk_level] || "";

        // Update summary counts
        updateSummaryCounts(data.findings);

        // Update findings
        findingsList.innerHTML = "";
        if (data.findings && data.findings.length > 0) {
            data.findings.forEach((finding) => {
                const findingEl = document.createElement("div");
                findingEl.className = "finding-item " + finding.severity.toLowerCase();
                findingEl.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-category">${finding.category}</span>
                        <span class="finding-points">+${finding.points} points</span>
                    </div>
                    <p class="finding-description">${finding.description}</p>
                    <code class="finding-evidence">${escapeHtml(finding.evidence)}</code>
                `;
                findingsList.appendChild(findingEl);
            });
        } else {
            findingsList.innerHTML = "<p class='empty-message'>No suspicious behavior detected.</p>";
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
        exportJsonBtn.style.display = "inline-flex";
        exportPdfBtn.style.display = "inline-flex";

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

    function updateSummaryCounts(findings) {
        const counts = {
            iframe: 0,
            javascript: 0,
            external_script: 0,
            dangerous_link: 0,
            cryptojacking: 0,
        };

        if (findings) {
            findings.forEach((f) => {
                if (counts.hasOwnProperty(f.category)) {
                    counts[f.category]++;
                }
            });
        }

        countIframe.textContent = counts.iframe;
        countJs.textContent = counts.javascript;
        countScripts.textContent = counts.external_script;
        countLinks.textContent = counts.dangerous_link;
        countMining.textContent = counts.cryptojacking;
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
                historyList.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">📊</div>
                        <p class="empty-message">No scan history yet.</p>
                        <p class="empty-hint">Enter a URL above to start scanning!</p>
                    </div>
                `;
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

            // Scroll to results
            resultsSection.scrollIntoView({ behavior: "smooth" });
        } catch (error) {
            showError("Failed to load scan details.");
        }
    }
});
