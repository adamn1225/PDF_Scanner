function showLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    }
}

function hideLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
}

// Wrap file upload logic with loading indicators
async function uploadFileWithLoading(file) {
    showLoading();
    const result = await uploadFile(file);
    hideLoading();
    return result;
}