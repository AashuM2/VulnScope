function startScan() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput ? urlInput.value.trim() : '';
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    const statusBox = document.getElementById('scanStatus');
    const statusText = document.getElementById('statusText');
    const progressBar = document.getElementById('progressBar');
    statusBox.style.display = 'block';
    statusText.textContent = 'Scanning ' + url + '...';
    progressBar.style.width = '0%';

    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 8;
        if (progress > 90) progress = 90;
        progressBar.style.width = progress + '%';
    }, 400);

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(async response => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Scan request failed. Please try again.');
        }
        return data;
    })
    .then(data => {
        clearInterval(interval);
        progressBar.style.width = '100%';
        statusText.textContent = data.cached
            ? 'Loaded from cache — this URL was scanned recently.'
            : 'Scan complete! Loading results...';
        setTimeout(() => {
            window.location.href = '/results/' + encodeURIComponent(data.scan_id);
        }, 600);
    })
    .catch(error => {
        clearInterval(interval);
        statusText.textContent = 'Error: ' + error.message;
        progressBar.style.width = '0%';
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const input = document.getElementById('urlInput');
    if (input) {
        input.addEventListener('keypress', function (event) {
            if (event.key === 'Enter') startScan();
        });
    }
});
