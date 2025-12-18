const API_BASE_URL = '/api/v1';
const urlParams = new URLSearchParams(window.location.search);
const scanId = urlParams.get('scanId');

let analysisData = null;
let selectedPackages = {};
let cachedMergedSBOM = null;

// Update back button with scan ID
if (scanId) {
    const backButton = document.querySelector('a[href*="repository-scanner"]');
    if (backButton) {
        backButton.href = `/static/repository-scanner.html?scanId=${scanId}`;
    }
}

if (!scanId) {
    showError('No scan ID provided');
} else {
    loadAnalysisData();
}

async function loadAnalysisData() {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/scan-analysis/${scanId}`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch analysis data');
        }
        
        analysisData = await response.json();
        
        // Initialize selected packages (all selected by default)
        for (const [scanner, packages] of Object.entries(analysisData.unique_packages || {})) {
            selectedPackages[scanner] = {};
            packages.forEach(pkg => {
                const key = `${pkg.name}@${pkg.version}`;
                selectedPackages[scanner][key] = true;
            });
        }
        
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('packageSelection').classList.remove('hidden');
        
        displayPackageSelection();
        updateStats();
        
    } catch (error) {
        console.error('Failed to load analysis:', error);
        showError(`Error: ${error.message}`);
    }
}

function displayPackageSelection() {
    const container = document.getElementById('uniquePackagesList');
    container.innerHTML = '';
    
    const uniquePackages = analysisData.unique_packages || {};
    
    for (const [scanner, packages] of Object.entries(uniquePackages)) {
        const section = document.createElement('div');
        section.className = 'scanner-section';
        
        const header = document.createElement('div');
        header.className = 'scanner-header';
        header.innerHTML = `
            <span class="scanner-name">${scanner}</span>
            <span class="badge badge-blue">${packages.length} packages</span>
        `;
        
        const controls = document.createElement('div');
        controls.className = 'scanner-controls';
        controls.innerHTML = `
            <button class="btn btn-small" onclick="selectAllForScanner('${scanner}')">✓ Select All</button>
            <button class="btn btn-small btn-outline" onclick="deselectAllForScanner('${scanner}')">✗ Deselect All</button>
        `;
        
        const packageList = document.createElement('div');
        packageList.className = 'package-list';
        
        packages.forEach(pkg => {
            const key = `${pkg.name}@${pkg.version}`;
            const isGitHubAction = isGitHubActionPackage(pkg.name);
            
            const item = document.createElement('div');
            item.className = 'package-item';
            
            const label = document.createElement('label');
            label.innerHTML = `
                <input type="checkbox" 
                       data-scanner="${scanner}" 
                       data-key="${key}"
                       ${selectedPackages[scanner][key] ? 'checked' : ''}
                       onchange="togglePackage('${scanner}', '${key}')">
                <span class="package-name ${isGitHubAction ? 'action-package' : ''}">${key}</span>
            `;
            
            item.appendChild(label);
            packageList.appendChild(item);
        });
        
        section.appendChild(header);
        section.appendChild(controls);
        section.appendChild(packageList);
        container.appendChild(section);
    }
}

function togglePackage(scanner, key) {
    selectedPackages[scanner][key] = !selectedPackages[scanner][key];
    updateStats();
}

function selectAll() {
    for (const scanner in selectedPackages) {
        for (const key in selectedPackages[scanner]) {
            selectedPackages[scanner][key] = true;
        }
    }
    updateCheckboxes();
    updateStats();
}

function deselectAll() {
    for (const scanner in selectedPackages) {
        for (const key in selectedPackages[scanner]) {
            selectedPackages[scanner][key] = false;
        }
    }
    updateCheckboxes();
    updateStats();
}

function selectAllForScanner(scanner) {
    if (selectedPackages[scanner]) {
        for (const key in selectedPackages[scanner]) {
            selectedPackages[scanner][key] = true;
        }
    }
    updateCheckboxes();
    updateStats();
}

function deselectAllForScanner(scanner) {
    if (selectedPackages[scanner]) {
        for (const key in selectedPackages[scanner]) {
            selectedPackages[scanner][key] = false;
        }
    }
    updateCheckboxes();
    updateStats();
}

function filterGitHubActions() {
    for (const [scanner, packages] of Object.entries(analysisData.unique_packages || {})) {
        packages.forEach(pkg => {
            const key = `${pkg.name}@${pkg.version}`;
            selectedPackages[scanner][key] = !isGitHubActionPackage(pkg.name);
        });
    }
    updateCheckboxes();
    updateStats();
}

function isGitHubActionPackage(name) {
    const patterns = ['actions/', 'github/', '.github/', 'workflow/', 'action-'];
    const nameLower = name.toLowerCase();
    return patterns.some(pattern => nameLower.includes(pattern));
}

function updateCheckboxes() {
    document.querySelectorAll('input[type="checkbox"][data-scanner]').forEach(cb => {
        const scanner = cb.dataset.scanner;
        const key = cb.dataset.key;
        cb.checked = selectedPackages[scanner][key];
    });
}

function updateStats() {
    const exactCount = (analysisData.common_packages?.exact || []).length;
    const fuzzyCount = (analysisData.fuzzy_matches?.fuzzy || []).length;
    
    let totalUnique = 0;
    let totalSelected = 0;
    
    for (const scanner in selectedPackages) {
        for (const key in selectedPackages[scanner]) {
            totalUnique++;
            if (selectedPackages[scanner][key]) {
                totalSelected++;
            }
        }
    }
    
    document.getElementById('exactCount').textContent = exactCount;
    document.getElementById('fuzzyCount').textContent = fuzzyCount;
    document.getElementById('uniqueCount').textContent = totalUnique;
    document.getElementById('selectedCount').textContent = totalSelected;
}

async function generateMergedSBOM() {
    try {
        // Build list of selected unique packages
        const selectedUniquePackages = {};
        for (const [scanner, packages] of Object.entries(analysisData.unique_packages || {})) {
            selectedUniquePackages[scanner] = packages
                .filter(pkg => {
                    const key = `${pkg.name}@${pkg.version}`;
                    return selectedPackages[scanner][key];
                })
                .map(pkg => ({ name: pkg.name, version: pkg.version }));
        }
        
        // Call backend with selected packages
        const response = await fetch(`${API_BASE_URL}/scan/merge-sbom/${scanId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                selected_unique_packages: selectedUniquePackages
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to generate merged SBOM');
        }
        
        cachedMergedSBOM = await response.json();
        
        // Display the merged SBOM with CPE information
        document.getElementById('packageSelection').classList.add('hidden');
        document.getElementById('mergedSBOMDisplay').classList.remove('hidden');
        
        // Set service links with scanId
        const cpeLink = document.querySelector('a[href*="cpe-service"]');
        const purlLink = document.querySelector('a[href*="purl-service"]');
        if (cpeLink) cpeLink.href = `/static/cpe-service.html?scanId=${scanId}`;
        if (purlLink) purlLink.href = `/static/purl-service.html?scanId=${scanId}`;
        
        displayMergedSBOMWithCPEs();
        
    } catch (error) {
        console.error('Failed to generate merged SBOM:', error);
        alert(`Error: ${error.message}`);
    }
}

function displayMergedSBOMWithCPEs() {
    const container = document.getElementById('sbomContent');
    container.innerHTML = '';
    
    if (!cachedMergedSBOM || !cachedMergedSBOM.components) {
        container.textContent = JSON.stringify(cachedMergedSBOM, null, 2);
        return;
    }
    
    // Create table view for components with CPEs
    const componentsWithCPEs = cachedMergedSBOM.components.filter(c => c.cpe);
    
    if (componentsWithCPEs.length === 0) {
        container.innerHTML = '<div style="padding: 1rem;"><p>No components with CPE information found.</p></div>';
        const jsonView = document.createElement('pre');
        jsonView.style.cssText = 'margin-top: 1rem; background: #f9fafb; padding: 1rem; border-radius: 6px; overflow-x: auto;';
        jsonView.textContent = JSON.stringify(cachedMergedSBOM, null, 2);
        container.appendChild(jsonView);
        return;
    }
    
    const header = document.createElement('div');
    header.innerHTML = `
        <h3 style="margin-bottom: 1rem;">Components with CPEs (${componentsWithCPEs.length})</h3>
        <button class="btn" onclick="validateAllCPEs()" style="margin-bottom: 1rem;">🔍 Validate All CPEs</button>
        <button class="btn btn-outline" onclick="showFullJSON()" style="margin-bottom: 1rem;">📄 Show Full JSON</button>
    `;
    container.appendChild(header);
    
    const table = document.createElement('table');
    table.style.cssText = 'width: 100%; border-collapse: collapse; margin-top: 1rem;';
    table.innerHTML = `
        <thead>
            <tr style="background: #f3f4f6; border-bottom: 2px solid #e5e7eb;">
                <th style="padding: 0.75rem; text-align: left;">Component</th>
                <th style="padding: 0.75rem; text-align: left;">CPE</th>
                <th style="padding: 0.75rem; text-align: center;">Status</th>
                <th style="padding: 0.75rem; text-align: center;">Action</th>
            </tr>
        </thead>
        <tbody id="cpeTableBody"></tbody>
    `;
    container.appendChild(table);
    
    const tbody = table.querySelector('#cpeTableBody');
    componentsWithCPEs.forEach((component, idx) => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid #e5e7eb';
        row.id = `cpe-row-${idx}`;
        row.innerHTML = `
            <td style="padding: 0.75rem;">
                <div style="font-weight: 600;">${component.name}</div>
                <div style="font-size: 0.875rem; color: #6b7280;">${component.version}</div>
            </td>
            <td style="padding: 0.75rem; font-family: monospace; font-size: 0.813rem;">${component.cpe}</td>
            <td style="padding: 0.75rem; text-align: center;">
                <span id="cpe-status-${idx}" class="badge badge-blue">Not Validated</span>
            </td>
            <td style="padding: 0.75rem; text-align: center;">
                <button class="btn btn-small" onclick="validateSingleCPE(${idx}, '${component.cpe}')">Validate</button>
                <button class="btn btn-small btn-outline" onclick="removeCPE(${idx})" style="display: none;" id="remove-btn-${idx}">Remove</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function validateSingleCPE(idx, cpe) {
    const statusEl = document.getElementById(`cpe-status-${idx}`);
    const removeBtn = document.getElementById(`remove-btn-${idx}`);
    
    statusEl.textContent = 'Validating...';
    statusEl.className = 'badge badge-blue';
    
    try {
        const response = await fetch(`${API_BASE_URL}/scan/validate-cpes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cpes: [cpe]
            })
        });
        
        if (!response.ok) {
            throw new Error('Validation failed');
        }
        
        const result = await response.json();
        const isValid = result.results[cpe];
        
        if (isValid) {
            statusEl.textContent = '✓ Valid';
            statusEl.className = 'badge';
            statusEl.style.backgroundColor = '#d1fae5';
            statusEl.style.color = '#065f46';
        } else {
            statusEl.textContent = '✗ Invalid';
            statusEl.className = 'badge';
            statusEl.style.backgroundColor = '#fee2e2';
            statusEl.style.color = '#991b1b';
            removeBtn.style.display = 'inline-block';
        }
    } catch (error) {
        console.error('Validation error:', error);
        statusEl.textContent = 'Error';
        statusEl.className = 'badge';
        statusEl.style.backgroundColor = '#fef3c7';
        statusEl.style.color = '#92400e';
    }
}

async function validateAllCPEs() {
    const componentsWithCPEs = cachedMergedSBOM.components.filter(c => c.cpe);
    const cpes = componentsWithCPEs.map(c => c.cpe);
    
    if (cpes.length === 0) {
        alert('No CPEs to validate');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/scan/validate-cpes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cpes: cpes
            })
        });
        
        if (!response.ok) {
            throw new Error('Validation failed');
        }
        
        const result = await response.json();
        
        componentsWithCPEs.forEach((component, idx) => {
            const isValid = result.results[component.cpe];
            const statusEl = document.getElementById(`cpe-status-${idx}`);
            const removeBtn = document.getElementById(`remove-btn-${idx}`);
            
            if (isValid) {
                statusEl.textContent = '✓ Valid';
                statusEl.className = 'badge';
                statusEl.style.backgroundColor = '#d1fae5';
                statusEl.style.color = '#065f46';
            } else {
                statusEl.textContent = '✗ Invalid';
                statusEl.className = 'badge';
                statusEl.style.backgroundColor = '#fee2e2';
                statusEl.style.color = '#991b1b';
                if (removeBtn) removeBtn.style.display = 'inline-block';
            }
        });
        
        alert('Validation complete!');
    } catch (error) {
        console.error('Validation error:', error);
        alert('Failed to validate CPEs');
    }
}

function removeCPE(idx) {
    if (!confirm('Remove this invalid CPE from the component?')) {
        return;
    }
    
    const componentsWithCPEs = cachedMergedSBOM.components.filter(c => c.cpe);
    const component = componentsWithCPEs[idx];
    
    // Find the component in the merged SBOM and remove its CPE
    const componentInSBOM = cachedMergedSBOM.components.find(c => 
        c.name === component.name && c.version === component.version && c.cpe === component.cpe
    );
    
    if (componentInSBOM) {
        delete componentInSBOM.cpe;
        displayMergedSBOMWithCPEs();
        alert('CPE removed from component');
    }
}

function showFullJSON() {
    const container = document.getElementById('sbomContent');
    container.innerHTML = '';
    
    const jsonView = document.createElement('pre');
    jsonView.style.cssText = 'background: #f9fafb; padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: Monaco, monospace; font-size: 0.875rem;';
    jsonView.textContent = JSON.stringify(cachedMergedSBOM, null, 2);
    
    const header = document.createElement('div');
    header.innerHTML = `
        <button class="btn btn-outline" onclick="displayMergedSBOMWithCPEs()" style="margin-bottom: 1rem;">← Back to CPE View</button>
    `;
    
    container.appendChild(header);
    container.appendChild(jsonView);
}

function showPackageSelection() {
    document.getElementById('mergedSBOMDisplay').classList.add('hidden');
    document.getElementById('packageSelection').classList.remove('hidden');
}

async function downloadMergedSBOM() {
    if (!cachedMergedSBOM) {
        alert('Please generate the merged SBOM first');
        return;
    }
    
    try {
        const blob = new Blob([JSON.stringify(cachedMergedSBOM, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `merged-sbom-${scanId}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Download failed:', error);
        alert('Download failed');
    }
}

function showError(message) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('error').innerHTML = `<p>${message}</p>`;
}

// ==================== TAB NAVIGATION ====================
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    
    // Mark button as active
    const buttons = document.querySelectorAll('.tab-btn');
    if (tabName === 'sbomView') buttons[0].classList.add('active');
    else if (tabName === 'cpeValidation') buttons[1].classList.add('active');
    else if (tabName === 'purlValidation') buttons[2].classList.add('active');
}

function proceedToCPEValidation() {
    extractAndDisplayCPEs();
    showTab('cpeValidation');
}

function proceedToPURLValidation() {
    extractAndDisplayPURLs();
    showTab('purlValidation');
}

// ==================== CPE VALIDATION ====================
let cpeValidationResults = {};

function extractAndDisplayCPEs() {
    const components = cachedMergedSBOM.components || [];
    const cpes = [];
    
    components.forEach(component => {
        if (component.cpe) {
            cpes.push(component.cpe);
        }
    });
    
    document.getElementById('totalCPECount').textContent = cpes.length;
    
    const cpeResultsList = document.getElementById('cpeResultsList');
    cpeResultsList.innerHTML = '';
    
    if (cpes.length === 0) {
        cpeResultsList.innerHTML = '<p>No CPEs found in the merged SBOM.</p>';
        return;
    }
    
    cpes.forEach((cpe, idx) => {
        const cpeItem = document.createElement('div');
        cpeItem.className = 'package-item';
        cpeItem.id = `cpe-item-${idx}`;
        
        // Check if we have cached validation result
        const isValid = cpeValidationResults[cpe];
        const statusClass = isValid === true ? 'valid' : isValid === false ? 'invalid' : 'pending';
        const statusText = isValid === true ? 'Valid' : isValid === false ? 'Invalid' : 'Pending validation';
        
        cpeItem.innerHTML = `
            <div class="package-info">
                <strong>${cpe}</strong>
                <span class="status ${statusClass}">${statusText}</span>
            </div>
            <button class="btn-small" onclick="removeSingleCPE('${cpe}', ${idx})">Remove</button>
        `;
        cpeResultsList.appendChild(cpeItem);
    });
    
    updateCPECounts();
}

async function validateCPEs() {
    const components = cachedMergedSBOM.components || [];
    const cpes = [];
    
    components.forEach(component => {
        if (component.cpe) {
            cpes.push(component.cpe);
        }
    });
    
    if (cpes.length === 0) {
        alert('No CPEs to validate');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/scan/cpe-validate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cpes: cpes })
        });
        
        if (!response.ok) {
            throw new Error('Failed to validate CPEs');
        }
        
        const data = await response.json();
        cpeValidationResults = data.results;
        
        // Update display with cached results
        extractAndDisplayCPEs();
        
    } catch (error) {
        console.error('Failed to validate CPEs:', error);
        alert(`Error validating CPEs: ${error.message}`);
    }
}

function updateCPECounts() {
    let validCount = 0;
    let invalidCount = 0;
    
    Object.values(cpeValidationResults).forEach(isValid => {
        if (isValid === true) validCount++;
        else if (isValid === false) invalidCount++;
    });
    
    document.getElementById('validCPECount').textContent = validCount;
    document.getElementById('invalidCPECount').textContent = invalidCount;
}

function removeSingleCPE(cpe, idx) {
    if (!confirm('Remove this CPE from the component?')) {
        return;
    }
    
    // Remove from SBOM
    cachedMergedSBOM.components = cachedMergedSBOM.components.filter(component => component.cpe !== cpe);
    
    // Remove from validation results
    delete cpeValidationResults[cpe];
    
    // Update display
    extractAndDisplayCPEs();
    alert('CPE removed');
}

function removeInvalidCPEs() {
    const invalidCPEs = Object.keys(cpeValidationResults).filter(cpe => cpeValidationResults[cpe] === false);
    
    if (invalidCPEs.length === 0) {
        alert('No invalid CPEs to remove. Please validate first.');
        return;
    }
    
    if (!confirm(`Remove ${invalidCPEs.length} invalid CPE(s)?`)) {
        return;
    }
    
    // Remove invalid CPEs from SBOM
    cachedMergedSBOM.components = cachedMergedSBOM.components.filter(component => {
        if (!component.cpe) return true;
        return cpeValidationResults[component.cpe] !== false;
    });
    
    // Remove from validation results
    invalidCPEs.forEach(cpe => delete cpeValidationResults[cpe]);
    
    // Update display
    extractAndDisplayCPEs();
    alert(`${invalidCPEs.length} invalid CPE(s) removed`);
}

function removeAllCPEs() {
    const totalCPEs = cachedMergedSBOM.components.filter(c => c.cpe).length;
    
    if (totalCPEs === 0) {
        alert('No CPEs to remove');
        return;
    }
    
    if (!confirm(`Remove all ${totalCPEs} CPE(s) from the SBOM?`)) {
        return;
    }
    
    // Remove all CPEs from components
    cachedMergedSBOM.components.forEach(component => {
        delete component.cpe;
    });
    
    // Clear validation results
    cpeValidationResults = {};
    
    // Update display
    extractAndDisplayCPEs();
    alert(`All ${totalCPEs} CPE(s) removed`);
}

// ==================== PURL VALIDATION ====================
let purlValidationResults = {};

function extractAndDisplayPURLs() {
    const components = cachedMergedSBOM.components || [];
    const purls = [];
    
    components.forEach(component => {
        if (component.purl) {
            purls.push(component.purl);
        }
    });
    
    document.getElementById('totalPURLCount').textContent = purls.length;
    
    const purlResultsList = document.getElementById('purlResultsList');
    purlResultsList.innerHTML = '';
    
    if (purls.length === 0) {
        purlResultsList.innerHTML = '<p>No PURLs found in the merged SBOM.</p>';
        return;
    }
    
    purls.forEach((purl, idx) => {
        const purlItem = document.createElement('div');
        purlItem.className = 'package-item';
        purlItem.id = `purl-item-${idx}`;
        
        // Check if we have cached validation result
        const isValid = purlValidationResults[purl];
        const statusClass = isValid === true ? 'valid' : isValid === false ? 'invalid' : 'pending';
        const statusText = isValid === true ? 'Valid' : isValid === false ? 'Invalid' : 'Pending validation';
        
        purlItem.innerHTML = `
            <div class="package-info">
                <strong>${purl}</strong>
                <span class="status ${statusClass}">${statusText}</span>
            </div>
            <button class="btn-small" onclick="removeSinglePURL('${purl.replace(/'/g, "\\'")}', ${idx})">Remove</button>
        `;
        purlResultsList.appendChild(purlItem);
    });
    
    updatePURLCounts();
}

async function validatePURLs() {
    const components = cachedMergedSBOM.components || [];
    const purls = [];
    
    components.forEach(component => {
        if (component.purl) {
            purls.push(component.purl);
        }
    });
    
    if (purls.length === 0) {
        alert('No PURLs to validate');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/scan/purl-validate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ purls: purls })
        });
        
        if (!response.ok) {
            throw new Error('Failed to validate PURLs');
        }
        
        const data = await response.json();
        purlValidationResults = data.results;
        
        // Update display with cached results
        extractAndDisplayPURLs();
        
    } catch (error) {
        console.error('Failed to validate PURLs:', error);
        alert(`Error validating PURLs: ${error.message}`);
    }
}

function updatePURLCounts() {
    let validCount = 0;
    let invalidCount = 0;
    
    Object.values(purlValidationResults).forEach(isValid => {
        if (isValid === true) validCount++;
        else if (isValid === false) invalidCount++;
    });
    
    document.getElementById('validPURLCount').textContent = validCount;
    document.getElementById('invalidPURLCount').textContent = invalidCount;
}

function removeSinglePURL(purl, idx) {
    if (!confirm('Remove this PURL from the component?')) {
        return;
    }
    
    // Remove from SBOM
    cachedMergedSBOM.components = cachedMergedSBOM.components.filter(component => component.purl !== purl);
    
    // Remove from validation results
    delete purlValidationResults[purl];
    
    // Update display
    extractAndDisplayPURLs();
    alert('PURL removed');
}

function removeInvalidPURLs() {
    const invalidPURLs = Object.keys(purlValidationResults).filter(purl => purlValidationResults[purl] === false);
    
    if (invalidPURLs.length === 0) {
        alert('No invalid PURLs to remove. Please validate first.');
        return;
    }
    
    if (!confirm(`Remove ${invalidPURLs.length} invalid PURL(s)?`)) {
        return;
    }
    
    // Remove invalid PURLs from SBOM
    cachedMergedSBOM.components = cachedMergedSBOM.components.filter(component => {
        if (!component.purl) return true;
        return purlValidationResults[component.purl] !== false;
    });
    
    // Remove from validation results
    invalidPURLs.forEach(purl => delete purlValidationResults[purl]);
    
    // Update display
    extractAndDisplayPURLs();
    alert(`${invalidPURLs.length} invalid PURL(s) removed`);
}

function removeAllPURLs() {
    const totalPURLs = cachedMergedSBOM.components.filter(c => c.purl).length;
    
    if (totalPURLs === 0) {
        alert('No PURLs to remove');
        return;
    }
    
    if (!confirm(`Remove all ${totalPURLs} PURL(s) from the SBOM?`)) {
        return;
    }
    
    // Remove all PURLs from components
    cachedMergedSBOM.components.forEach(component => {
        delete component.purl;
    });
    
    // Clear validation results
    purlValidationResults = {};
    
    // Update display
    extractAndDisplayPURLs();
    alert(`All ${totalPURLs} PURL(s) removed`);
}
