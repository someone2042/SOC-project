let largeSbaChartInstance = null;
let currentAgent = null;

async function fetchAgents() {
    try {
        const response = await fetch('/api/agents');
        if (!response.ok) return;
        const agents = await response.json();
        
        const selector = document.getElementById('agent-selector');
        if (agents.length === 0) {
            selector.innerHTML = '<option value="">No agents found</option>';
            return;
        }
        
        // Preserve selection
        const selectedValue = selector.value;
        selector.innerHTML = agents.map(a => `<option value="${a}">${a}</option>`).join('');
        
        if (selectedValue && agents.includes(selectedValue)) {
            selector.value = selectedValue;
        } else {
            currentAgent = agents[0];
            selector.value = currentAgent;
        }
        
        // Re-fetch history for the selected agent
        fetchSbaHistory();
    } catch (error) {
        console.error('Error fetching agents:', error);
    }
}

document.getElementById('agent-selector').addEventListener('change', (e) => {
    currentAgent = e.target.value;
    fetchSbaHistory();
});

document.getElementById('refresh-btn').addEventListener('click', () => {
    const icon = document.querySelector('#refresh-btn i');
    icon.classList.add('fa-spin');
    Promise.all([fetchAgents(), fetchSbaHistory()]).then(() => {
        setTimeout(() => icon.classList.remove('fa-spin'), 500);
    });
});

async function fetchSbaHistory() {
    if (!currentAgent) return;
    
    try {
        const response = await fetch(`/api/sba-history?agent_name=${encodeURIComponent(currentAgent)}`);
        if (!response.ok) return;
        const historyData = await response.json();
        renderChart(historyData);
        renderTable(historyData);
    } catch (error) {
        console.error('Error fetching SBA history:', error);
    }
}

function renderChart(historyData) {
    const ctx = document.getElementById('largeSbaChart');
    if (!ctx) return;
    
    const labels = historyData.map(h => {
        const d = new Date(h.timestamp);
        return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
    });
    const scores = historyData.map(h => h.score);
    
    const latestScore = scores.length > 0 ? scores[scores.length - 1] : 0;
    const isCritical = latestScore > 75;
    const lineColor = isCritical ? '#f43f5e' : '#34d399';
    const bgColor = isCritical ? 'rgba(244, 63, 94, 0.2)' : 'rgba(52, 211, 153, 0.2)';
    
    // Update badge and indicator
    const badge = document.getElementById('current-score-badge');
    badge.textContent = `Current Score: ${latestScore}`;
    badge.className = `px-3 py-1 rounded text-sm font-bold border ${isCritical ? 'bg-rose-900/30 text-rose-400 border-rose-500/50' : 'bg-emerald-900/30 text-emerald-400 border-emerald-500/50'}`;
    
    const indicator = document.getElementById('status-indicator');
    indicator.className = `w-3 h-3 rounded-full animate-pulse ${isCritical ? 'bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.8)]' : 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]'}`;

    if (largeSbaChartInstance) {
        largeSbaChartInstance.data.labels = labels;
        largeSbaChartInstance.data.datasets[0].data = scores;
        largeSbaChartInstance.data.datasets[0].borderColor = lineColor;
        largeSbaChartInstance.data.datasets[0].backgroundColor = bgColor;
        largeSbaChartInstance.data.datasets[0].pointBackgroundColor = lineColor;
        largeSbaChartInstance.update();
        return;
    }

    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    largeSbaChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'SBA Score',
                data: scores,
                borderColor: lineColor,
                backgroundColor: bgColor,
                borderWidth: 3,
                pointRadius: 4,
                pointHoverRadius: 6,
                pointBackgroundColor: lineColor,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return 'Score: ' + context.parsed.y;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: 'rgba(51, 65, 85, 0.3)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
}

function renderTable(historyData) {
    const tbody = document.getElementById('factors-table-body');
    
    if (historyData.length === 0) {
        tbody.innerHTML = '<tr class="border-b border-slate-700/30"><td colspan="4" class="px-6 py-8 text-center italic">No telemetry recorded yet.</td></tr>';
        return;
    }
    
    // Reverse to show most recent first in the table
    const tableData = [...historyData].reverse();
    
    tbody.innerHTML = tableData.map(h => {
        const dateObj = new Date(h.timestamp);
        const timeStr = `${dateObj.getHours().toString().padStart(2, '0')}:${dateObj.getMinutes().toString().padStart(2, '0')}`;
        
        const scoreBadge = h.score > 75 
            ? `<span class="px-2 py-1 bg-rose-500/20 text-rose-400 rounded text-xs font-bold border border-rose-500/30">${h.score}</span>`
            : `<span class="px-2 py-1 bg-emerald-500/20 text-emerald-400 rounded text-xs font-bold border border-emerald-500/30">${h.score}</span>`;
            
        const natureColor = h.nature === 'Concentrated Spike' ? 'text-amber-400' : 'text-slate-400';
        
        const factorsList = h.factors && h.factors.length > 0 
            ? `<ul class="list-disc list-inside space-y-1 text-slate-300">${h.factors.slice(0,3).map(f => `<li>${f.replace(/</g, '&lt;')}</li>`).join('')}</ul>`
            : '<span class="text-slate-500 italic">No significant factors</span>';
            
        return `
            <tr class="border-b border-slate-700/30 hover:bg-slate-800/40 transition-colors">
                <td class="px-6 py-4 whitespace-nowrap text-slate-300 font-mono">${timeStr}</td>
                <td class="px-6 py-4 whitespace-nowrap">${scoreBadge}</td>
                <td class="px-6 py-4 whitespace-nowrap font-medium ${natureColor}">${h.nature || '-'}</td>
                <td class="px-6 py-4 text-xs">${factorsList}</td>
            </tr>
        `;
    }).join('');
}

// Polling
setInterval(() => {
    fetchAgents();
}, 5000);

// Init
fetchAgents();
