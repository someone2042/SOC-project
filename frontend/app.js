let currentAlerts = [];

async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        if (!response.ok) throw new Error('Network response was not ok');
        const data = await response.json();
        renderAlerts(data);
        updateStats(data);
        currentAlerts = data;
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

function updateStats(alerts) {
    document.getElementById('stat-total').textContent = alerts.length;
    const fps = alerts.filter(a => a.decision.verdict === 'FALSE_POSITIVE').length;
    const tps = alerts.filter(a => a.decision.verdict === 'TRUE_POSITIVE').length;
    document.getElementById('stat-fp').textContent = fps;
    document.getElementById('stat-tp').textContent = tps;
}

function getVerdictBadge(verdict) {
    if (verdict === 'TRUE_POSITIVE') return '<span class="px-2 py-1 bg-rose-500/20 text-rose-400 rounded text-xs font-bold border border-rose-500/30">TRUE POSITIVE</span>';
    if (verdict === 'FALSE_POSITIVE') return '<span class="px-2 py-1 bg-emerald-500/20 text-emerald-400 rounded text-xs font-bold border border-emerald-500/30">FALSE POSITIVE</span>';
    return '<span class="px-2 py-1 bg-amber-500/20 text-amber-400 rounded text-xs font-bold border border-amber-500/30">NEEDS HUMAN</span>';
}

function renderAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    
    if (alerts.length === 0) {
        container.innerHTML = '<div class="flex items-center justify-center h-full text-slate-500 italic">No alerts processed yet. Waiting for Wazuh...</div>';
        return;
    }

    container.innerHTML = alerts.map((alert, index) => `
        <div class="alert-card glass-panel rounded-xl border border-slate-700/50 p-5 cursor-pointer verdict-${alert.decision.verdict}" onclick="openModal(${index})">
            <div class="flex justify-between items-start mb-3">
                <div class="flex items-center gap-3">
                    ${getVerdictBadge(alert.decision.verdict)}
                    <span class="text-xs text-slate-400 font-mono">${alert.timestamp}</span>
                </div>
                <div class="text-xs font-mono text-slate-500">ID: ${alert.id.substring(0,8)}...</div>
            </div>
            
            <h3 class="text-lg font-semibold text-slate-200 mb-1">${alert.rule_description}</h3>
            <p class="text-sm text-slate-400 mb-4 line-clamp-2">${alert.decision.summary}</p>
            
            <div class="flex items-center gap-4 text-xs text-slate-500">
                <span class="flex items-center gap-1"><i class="fa-solid fa-server"></i> ${alert.agent_name}</span>
                <span class="flex items-center gap-1"><i class="fa-solid fa-network-wired"></i> ${alert.agent_ip}</span>
                <div class="flex items-center gap-3 ml-auto">
                    <span class="px-2 py-1 rounded text-xs font-bold border ${alert.ml_sba_score !== null ? (alert.ml_sba_score > 75 ? 'bg-rose-900/30 text-rose-400 border-rose-500/50' : 'bg-emerald-900/30 text-emerald-400 border-emerald-500/50') : 'bg-slate-800/80 text-slate-500 border-slate-700/50'}" title="System Behavior Analytics ML Score">
                        <i class="fa-solid fa-microchip mr-1"></i>SBA Score: ${alert.ml_sba_score !== null ? alert.ml_sba_score : 'N/A'}
                    </span>
                    <span class="text-cyan-400 font-medium hover:text-cyan-300 cursor-pointer">View Reasoning <i class="fa-solid fa-arrow-right"></i></span>
                </div>
            </div>
        </div>
    `).join('');
}

function openModal(index) {
    const alert = currentAlerts[index];
    const modal = document.getElementById('reasoning-modal');
    const content = document.getElementById('modal-content');
    
    document.getElementById('modal-title').textContent = alert.rule_description;
    document.getElementById('modal-subtitle').textContent = `Agent: ${alert.agent_name} (${alert.agent_ip}) | Alert ID: ${alert.id}`;
    
    let reasoningHTML = `
        <div class="p-4 bg-slate-900/50 rounded-lg border border-slate-700/50 mb-4">
            <div class="flex justify-between items-center mb-2">
                <div class="font-semibold text-slate-300">AI Executive Summary</div>
                ${getVerdictBadge(alert.decision.verdict)}
            </div>
            <p class="text-slate-300 text-sm leading-relaxed">${alert.decision.summary}</p>
            <div class="mt-4 flex gap-4 text-sm">
                <div class="px-3 py-1.5 bg-slate-800 rounded border border-slate-700"><span class="text-slate-400">Confidence:</span> <span class="text-white font-mono">${(alert.decision.confidence_score * 100).toFixed(0)}%</span></div>
                <div class="px-3 py-1.5 bg-slate-800 rounded border border-slate-700"><span class="text-slate-400">Action:</span> <span class="text-indigo-400 font-bold">${alert.decision.recommended_action}</span></div>
            </div>
        </div>
        <h4 class="font-semibold text-slate-300 mt-2 mb-4 border-b border-slate-700 pb-2"><i class="fa-solid fa-brain mr-2 text-cyan-400"></i>Reasoning Chain (Glass Box)</h4>
        <div class="flex flex-col gap-4">
    `;

    const chain = alert.decision.reasoning_chain || [];
    chain.forEach(step => {
        if (typeof step === 'string') {
            const isAction = step.toLowerCase().startsWith('action');
            const iconColor = isAction ? 'bg-indigo-500 shadow-[0_0_0_2px_rgba(99,102,241,0.5)]' : 'bg-cyan-500 shadow-[0_0_0_2px_rgba(6,182,212,0.5)]';
            const textColor = isAction ? 'text-indigo-200' : 'text-slate-300';
            
            reasoningHTML += `
                <div class="timeline-step">
                    <div class="absolute left-0 top-1 w-3 h-3 rounded-full border-2 border-[#0f172a] ${iconColor}"></div>
                    <div class="p-3 bg-slate-800/30 rounded border border-slate-700/50 ${textColor} text-sm font-mono leading-relaxed">
                        ${step.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
                    </div>
                </div>
            `;
        } else {
            // It's a structured object
            if (step.type === 'thought') {
                const thoughtStr = typeof step.content === 'string' ? step.content : JSON.stringify(step.content);
                reasoningHTML += `
                    <div class="timeline-step">
                        <div class="absolute left-0 top-1 w-3 h-3 rounded-full border-2 border-[#0f172a] bg-slate-400 shadow-[0_0_0_2px_rgba(148,163,184,0.5)]"></div>
                        <div class="p-3 bg-slate-800/30 rounded border border-slate-700/50 text-slate-300 text-sm font-mono leading-relaxed">
                            <span class="font-bold text-slate-400">Thought:</span> ${thoughtStr.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
                        </div>
                    </div>
                `;
            } else if (step.type === 'action') {
                const argsStr = typeof step.args === 'object' ? JSON.stringify(step.args, null, 2) : step.args;
                const safeArgs = argsStr.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                reasoningHTML += `
                    <div class="timeline-step">
                        <div class="absolute left-0 top-1 w-3 h-3 rounded-full border-2 border-[#0f172a] bg-indigo-500 shadow-[0_0_0_2px_rgba(99,102,241,0.5)]"></div>
                        <div class="p-3 bg-indigo-900/20 rounded border border-indigo-700/50 text-indigo-200 text-sm font-mono leading-relaxed">
                            <div class="font-bold mb-1"><i class="fa-solid fa-wrench mr-2"></i>Action: ${step.tool}</div>
                            <pre class="bg-slate-900/80 p-3 rounded text-xs mt-2 overflow-x-auto border border-slate-700/50 text-slate-300"><code>${safeArgs}</code></pre>
                        </div>
                    </div>
                `;
            } else if (step.type === 'observation') {
                const contentStr = typeof step.content === 'object' ? JSON.stringify(step.content, null, 2) : step.content;
                const safeContent = contentStr.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                reasoningHTML += `
                    <div class="timeline-step">
                        <div class="absolute left-0 top-1 w-3 h-3 rounded-full border-2 border-[#0f172a] bg-cyan-500 shadow-[0_0_0_2px_rgba(6,182,212,0.5)]"></div>
                        <div class="bg-slate-800/40 rounded border border-cyan-700/30 text-cyan-100 text-sm font-mono leading-relaxed overflow-hidden">
                            <details class="group">
                                <summary class="p-3 cursor-pointer font-bold bg-cyan-900/20 hover:bg-cyan-900/40 transition-colors flex items-center justify-between outline-none custom-summary">
                                    <span><i class="fa-solid fa-eye mr-2"></i>Observation: ${step.tool}</span>
                                    <i class="fa-solid fa-chevron-down text-xs transition-transform group-open:rotate-180"></i>
                                </summary>
                                <div class="p-3 border-t border-cyan-700/30">
                                    <pre class="bg-slate-900 p-3 rounded text-xs overflow-x-auto custom-scrollbar max-h-80 border border-slate-700 text-slate-300"><code>${safeContent}</code></pre>
                                </div>
                            </details>
                        </div>
                    </div>
                `;
            } else if (step.type === 'error') {
                reasoningHTML += `
                    <div class="timeline-step">
                        <div class="absolute left-0 top-1 w-3 h-3 rounded-full border-2 border-[#0f172a] bg-rose-500 shadow-[0_0_0_2px_rgba(244,63,94,0.5)]"></div>
                        <div class="p-3 bg-rose-900/20 rounded border border-rose-700/50 text-rose-200 text-sm font-mono leading-relaxed">
                            <span class="font-bold text-rose-400"><i class="fa-solid fa-triangle-exclamation mr-2"></i>Error:</span> ${step.content.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
                        </div>
                    </div>
                `;
            }
        }
    });

    reasoningHTML += '</div>';
    
    document.getElementById('modal-body').innerHTML = reasoningHTML;
    
    modal.classList.remove('hidden');
    // Trigger reflow
    void modal.offsetWidth;
    modal.classList.remove('opacity-0');
    content.classList.remove('scale-95');
}

document.getElementById('close-modal-btn').addEventListener('click', () => {
    const modal = document.getElementById('reasoning-modal');
    const content = document.getElementById('modal-content');
    
    modal.classList.add('opacity-0');
    content.classList.add('scale-95');
    
    setTimeout(() => {
        modal.classList.add('hidden');
    }, 300);
});

document.getElementById('refresh-btn').addEventListener('click', () => {
    const icon = document.querySelector('#refresh-btn i');
    icon.classList.add('fa-spin');
    fetchAlerts().then(() => {
        setTimeout(() => icon.classList.remove('fa-spin'), 500);
    });
});

// Poll every 5 seconds
setInterval(fetchAlerts, 5000);

// Initial fetch
fetchAlerts();
