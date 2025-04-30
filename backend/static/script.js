
// Helper function to format the PDF date
function formatPDFDate(pdfDate) {
    if (!pdfDate || !pdfDate.startsWith('D:')) {
        return pdfDate || 'Unknown'; // Return as-is if the format is invalid
    }

    // Extract the date components
    const year = pdfDate.substring(2, 6);
    const month = pdfDate.substring(6, 8);
    const day = pdfDate.substring(8, 10);
    const hour = pdfDate.substring(10, 12);
    const minute = pdfDate.substring(12, 14);
    const second = pdfDate.substring(14, 16);

    // Create a JavaScript Date object
    const date = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}`);

    // Format the date to a readable string
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
    });
}

// Define the desired order of keys
const keyOrder = [
    "suspicious_blocks",
    "suspicious_objects",
    "suspicious_streams",
    "suspicious_fonts",
    "suspicious_images",
    "suspicious_metadata",
    "total_blocks",
    "file_size_bytes",
    "file_size_kb",
    "page_count",
    "encrypted",
    "created",
    "modified",
    "Note",
    "is_modified",
];

// Store results for download
const allResults = [];

// Helper function to display results
function displayResults(result) {
    allResults.push(result); // Add result to the array for download

    const downloadBtn = document.getElementById('download-btn');
    const exportAnalysisBtn = document.getElementById('export-analysis-btn');

    // Unhide the buttons
    if (downloadBtn.hidden) {
        downloadBtn.hidden = false; // Remove the hidden attribute
    }
    if (exportAnalysisBtn.hidden) {
        exportAnalysisBtn.hidden = false; // Remove the hidden attribute
    }

    // Create a new list item for the file
    const listItem = document.createElement('li');
    listItem.style.marginBottom = '15px';

    // Add the filename as a header
    const fileHeader = document.createElement('h4');
    fileHeader.textContent = `File: ${result.filename}`;
    listItem.appendChild(fileHeader);

    // Create a sublist for the details
    const detailsList = document.createElement('ul');
    detailsList.style.listStyle = 'none';
    detailsList.style.paddingLeft = '0';

    // Add each key-value pair in the specified order
    keyOrder.forEach((key) => {
        if (key in result) {
            const detailItem = document.createElement('li');
            const value = result[key];
            if (key === 'modified' || key === 'created') {
                // Format the date for 'modified' and 'created' keys
                detailItem.textContent = `${key.replace(/_/g, ' ')}: ${formatPDFDate(value)}`;
            } else {
                detailItem.textContent = `${key.replace(/_/g, ' ')}: ${value}`;
            }

            // Highlight suspicious metadata
            if (key === 'Note' && value) {
                detailItem.style.fontWeight = 'bold';
            }

            detailsList.appendChild(detailItem);
        }
    });

    // Add the structure analysis as a collapsible section
    if (result.structure_analysis && result.structure_analysis !== "No structure analysis available") {
        const analysisHeader = document.createElement('h5');
        analysisHeader.textContent = "Structure Analysis:";
        analysisHeader.style.marginTop = '10px';
        listItem.appendChild(analysisHeader);

        const toggleButton = document.createElement('button');
        toggleButton.textContent = "Show/Hide Analysis";
        toggleButton.style.marginBottom = '10px';
        toggleButton.style.cursor = 'pointer';
        toggleButton.style.backgroundColor = '#2a9ef7';
        toggleButton.style.color = 'white';
        toggleButton.style.border = 'none';
        toggleButton.style.padding = '10px 20px';
        toggleButton.style.borderRadius = '5px';
        toggleButton.style.marginRight = '10px';
        listItem.appendChild(toggleButton);

        const analysisContent = document.createElement('pre');
        analysisContent.textContent = result.structure_analysis;
        analysisContent.style.backgroundColor = '#f4f4f9';
        analysisContent.style.padding = '10px';
        analysisContent.style.color = '#030308';
        analysisContent.style.border = '1px solid #ccc';
        analysisContent.style.borderRadius = '5px';
        analysisContent.style.overflowY = 'auto';
        analysisContent.style.maxHeight = '300px';
        analysisContent.style.display = 'none'; // Initially hidden
        listItem.appendChild(analysisContent);

        toggleButton.addEventListener('click', () => {
            analysisContent.style.display = analysisContent.style.display === 'none' ? 'block' : 'none';
        });

        if ('suspicious_hex_count' in result || 'suspicious_font_count' in result || 'is_obfuscated' in result) {
            const obfuscationHeader = document.createElement('h5');
            obfuscationHeader.textContent = "Obfuscation Results:";
            obfuscationHeader.style.marginTop = '10px';
            listItem.appendChild(obfuscationHeader);

            const obfuscationList = document.createElement('ul');
            obfuscationList.style.listStyle = 'none';
            obfuscationList.style.paddingLeft = '0';

            if ('suspicious_hex_count' in result) {
                const hexItem = document.createElement('li');
                hexItem.textContent = `Suspicious Hex Blocks: ${result.suspicious_hex_count}`;
                obfuscationList.appendChild(hexItem);
            }

            if ('suspicious_font_count' in result) {
                const fontItem = document.createElement('li');
                fontItem.textContent = `Suspicious Font References: ${result.suspicious_font_count}`;
                obfuscationList.appendChild(fontItem);
            }

            if ('is_obfuscated' in result) {
                const obfuscatedItem = document.createElement('li');
                obfuscatedItem.textContent = `Is Obfuscated: ${result.is_obfuscated ? 'Yes' : 'No'}`;
                obfuscatedItem.style.color = result.is_obfuscated ? 'red' : 'green';
                obfuscationList.appendChild(obfuscatedItem);
            }

            listItem.appendChild(obfuscationList);
        }

        if (result.structure_analysis.length > 1000) {
            const truncatedContent = result.structure_analysis.substring(0, 1000) + '...';
            analysisContent.textContent = truncatedContent;

            const expandButton = document.createElement('button');
            expandButton.textContent = "Show Full Analysis";
            expandButton.style.marginTop = '10px';
            expandButton.style.cursor = 'pointer';
            expandButton.style.backgroundColor = '#2a9ef7';
            expandButton.style.color = 'white';
            expandButton.style.border = 'none';
            expandButton.style.padding = '10px 20px';
            expandButton.style.maxHeight = '300px';

            expandButton.style.borderRadius = '5px';

            expandButton.addEventListener('click', () => {
                analysisContent.textContent = result.structure_analysis;
                expandButton.remove(); // Remove the button after expanding
            });

            listItem.appendChild(expandButton);
        }

        // Highlight suspicious objects in the structure analysis
        if (
            result.structure_analysis.includes('/JavaScript') ||
            result.structure_analysis.includes('/Launch') ||
            result.structure_analysis.includes('/OpenAction') ||
            result.structure_analysis.includes('/AA') ||
            result.structure_analysis.includes('/URI') ||
            result.structure_analysis.includes('/SubmitForm')
        ) {
            analysisHeader.style.color = 'red';
            analysisHeader.textContent += " (Suspicious Content Detected)";
        }
    } else {
        const noAnalysis = document.createElement('p');
        noAnalysis.textContent = "No structure analysis available.";
        noAnalysis.style.color = '#888';
        listItem.appendChild(noAnalysis);
    }

    listItem.appendChild(detailsList);
    resultsList.appendChild(listItem);

    if (result.is_suspicious) {
        const threatWarning = document.createElement('p');
        threatWarning.textContent = "Warning: Suspicious content detected!";
        threatWarning.style.color = 'red';
        threatWarning.style.fontWeight = 'bold';
        listItem.appendChild(threatWarning);
    }
    // Change background color based on a condition
    if (result.encrypted || result.suspicious_blocks > 10 || !result.is_suspicious) {
        // Create a status icon (circle)
        const statusIcon = document.createElement('span');
        statusIcon.classList.add('status-icon');

        // Create a text label for the status
        const statusText = document.createElement('span');
        statusText.style.marginLeft = '10px'; // Add spacing between the icon and text

        if (result.encrypted) {
            statusIcon.classList.add('status-encrypted');
            statusIcon.title = 'Encrypted File'; // Tooltip
            statusText.textContent = 'Encrypted File'; // Inline text
        } else if (result.suspicious_blocks > 10) {
            statusIcon.classList.add('status-suspicious');
            statusIcon.title = 'Suspicious File'; // Tooltip
            statusText.textContent = 'Suspicious File'; // Inline text
        } else {
            statusIcon.classList.add('status-safe');
            statusIcon.title = 'Safe File'; // Tooltip
            statusText.textContent = 'Safe File'; // Inline text
        }

        // Add the icon and text to the list item
        listItem.prepend(statusText);
        listItem.prepend(statusIcon);
    }
}

function exportAnalysis() {
    if (allResults.length === 0) {
        alert('No results to export!');
        return;
    }

    let content = 'PDF Structure Analysis\n\n';
    allResults.forEach((result, index) => {
        content += `File ${index + 1}: ${result.filename}\n`;
        content += `Structure Analysis:\n${result.structure_analysis || 'No structure analysis available.'}\n\n`;
    });

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'structure_analysis.txt';
    a.click();

    URL.revokeObjectURL(url); // Clean up the URL object
}

const exportAnalysisBtn = document.getElementById('export-analysis-btn');
exportAnalysisBtn.addEventListener('click', exportAnalysis);
// Function to download results as a text file
function downloadResults() {
    if (allResults.length === 0) {
        alert('No results to download!');
        return;
    }

    let content = 'PDF Forensics Scanner Results\n\n';
    allResults.forEach((result, index) => {
        content += `File ${index + 1}: ${result.filename}\n`;
        keyOrder.forEach((key) => {
            if (key in result) {
                const value = key === 'modified' || key === 'created' ? formatPDFDate(result[key]) : result[key];
                content += `  ${key.replace(/_/g, ' ')}: ${value}\n`;
            }
        });
        content += '\n';
    });

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'results.txt';
    a.click();

    URL.revokeObjectURL(url); // Clean up the URL object
}

const dropzone = document.getElementById('dropzone');
const resultsList = document.getElementById('results-list');
const downloadBtn = document.getElementById('download-btn');

downloadBtn.addEventListener('click', downloadResults);

dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'green';
    dropzone.style.backgroundColor = '#e8f5e9'; // Light green background
});

dropzone.addEventListener('dragleave', () => {
    dropzone.style.borderColor = '#ccc';
    dropzone.style.backgroundColor = 'white'; // Reset background
});

dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.style.borderColor = '#ccc';
    const files = e.dataTransfer.files;

    for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('http://localhost:5000/upload', { method: 'POST', body: formData });
            if (!response.ok) {
                const errorText = await response.text();
                alert(`Error uploading file: ${file.name} - ${errorText}`);
                continue;
            }
            const result = await response.json();
            displayResults(result); // Use the helper function to display results
        } catch (error) {
            alert(`Error uploading file: ${file.name} - ${error.message}`);
        }
    }
});

// Allow clicking on the dropzone to open the file picker
dropzone.addEventListener('click', () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.pdf';
    input.multiple = true;
    input.style.display = 'none';

    input.addEventListener('change', async (e) => {
        const files = e.target.files;

        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('http://localhost:5000/upload', { method: 'POST', body: formData });
                if (!response.ok) {
                    const errorText = await response.text();
                    alert(`Error uploading file: ${file.name} - ${errorText}`);
                    continue;
                }
                const result = await response.json();
                displayResults(result); // Use the helper function to display results
            } catch (error) {
                alert(`Error uploading file: ${file.name} - ${error.message}`);
            }
        }
    });

    input.click();
});

function updateSummary() {
    const totalFiles = allResults.length;
    const suspiciousFiles = allResults.filter(result => result.is_suspicious).length;

    const summary = document.getElementById('summary');
    summary.textContent = `Total Files: ${totalFiles}, Suspicious Files: ${suspiciousFiles}`;
    displayResults(result);
    updateSummary();
}

