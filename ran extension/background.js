chrome.downloads.onCreated.addListener(downloadItem => {
    checkFile(downloadItem);
});

function checkFile(downloadItem) {
    chrome.downloads.onChanged.addListener(function onChanged(downloadDelta) {
        if (downloadDelta.id === downloadItem.id && downloadDelta.state && downloadDelta.state.current === 'complete') {
            chrome.downloads.onChanged.removeListener(onChanged);
            chrome.downloads.search({ id: downloadItem.id }, function (results) {
                if (results && results.length > 0) {
                    const file = results[0];
                    fetchFileContent(file.url, function (content) {
                        scanFileContentWithVirusTotal(content, function (isMalicious) {
                            if (isMalicious) {
                                chrome.downloads.cancel(downloadItem.id, () => {
                                    alert("Malicious file detected! The download has been cancelled.");
                                });
                            }
                        });
                    });
                }
            });
        }
    });
}

function fetchFileContent(fileUrl, callback) {
    fetch(fileUrl)
        .then(response => response.arrayBuffer())
        .then(buffer => {
            const content = new Uint8Array(buffer);
            callback(content);
        })
        .catch(error => {
            console.error('Error fetching file content:', error);
            callback(null);
        });
}

function scanFileContentWithVirusTotal(content, callback) {
    const apiKey = '2aae223cb3c4d74d6904d1678a1a5aa17f300008953cd819da438bf326a4dd03'; // Replace with your actual API key
    const blob = new Blob([content]);

    fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/octet-stream'
        },
        body: blob
    })
        .then(response => response.json())
        .then(data => {
            console.log('VirusTotal API response:', data); // Debugging line
            if (data && data.data && data.data.id) {
                const scanId = data.data.id;
                pollMalwareAPI(scanId, callback);
            } else {
                console.error('Invalid response format from VirusTotal:', data); // Improved error message
                callback(false);
            }
        })
        .catch(error => {
            console.error('Error scanning file with VirusTotal:', error);
            callback(false);
        }
        );
}

function pollMalwareAPI(scanId, callback, attempts = 5, delay = 10000) {
    if (attempts === 0) {
        callback(false); // Assume non-malicious if max attempts reached
        return;
    }

    setTimeout(() => {
        fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
            method: 'GET',
            headers: { 'x-apikey': apiKey }
        })
            .then(response => response.json())
            .then(result => {
                const stats = result.data.attributes.stats;
                if (result.data.attributes.status === 'completed') {
                    const isMalicious = stats.malicious > 0;
                    callback(isMalicious);
                } else {
                    pollMalwareAPI(scanId, callback, attempts - 1, delay);
                }
            })
            .catch(error => {
                console.error('Error polling VirusTotal:', error);
                callback(false);
            });
    }, delay);
}
