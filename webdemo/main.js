let wasmModule = null;
let isReady = false;

async function loadWasm() {
    const statusElement = document.getElementById('status');
    const buttonElement = document.getElementById('makeRequest');

    try {
        statusElement.className = 'status loading';
        statusElement.textContent = 'Loading WASM module...';

        const go = new Go();
        const response = await fetch('main.wasm');
        const buffer = await response.arrayBuffer();

        const result = await WebAssembly.instantiate(buffer, go.importObject);
        wasmModule = result.instance;

        go.run(wasmModule);

        buttonElement.disabled = false;
        isReady = true;
        statusElement.className = 'status ready';
        statusElement.textContent = 'Ready. Enter WebSocket URL and Target URL, then click "Make Request"';

        console.log('WASM module loaded successfully');
    } catch (error) {
        console.error('Failed to load WASM:', error);
        statusElement.className = 'status error';
        statusElement.textContent = 'Failed to load WASM module: ' + error.message;
        buttonElement.disabled = true;
    }
}

function handleRequest() {
    if (!isReady) {
        alert('WASM module is not ready yet. Please wait...');
        return;
    }

    const wsUrl = document.getElementById('wsUrl').value;
    const targetUrl = document.getElementById('targetUrl').value;
    const statusElement = document.getElementById('status');
    const resultElement = document.getElementById('result');
    const buttonElement = document.getElementById('makeRequest');

    if (!wsUrl || !targetUrl) {
        alert('Please enter both WebSocket URL and Target URL');
        return;
    }

    buttonElement.disabled = true;
    statusElement.className = 'status loading';
    statusElement.textContent = 'Request initiated... Check console for details';
    resultElement.textContent = '';

    try {
        if (typeof makeSocksRequest !== 'function') {
            throw new Error('makeSocksRequest function not available');
        }

        makeSocksRequest(wsUrl, targetUrl);

        setTimeout(() => {
            buttonElement.disabled = false;
        }, 500);
    } catch (error) {
        console.error('Request failed:', error);
        statusElement.className = 'status error';
        statusElement.textContent = 'Request failed: ' + error.message;
        resultElement.textContent = 'Error: ' + error.message;
        buttonElement.disabled = false;
    }
}

window.addEventListener('load', () => {
    const buttonElement = document.getElementById('makeRequest');
    buttonElement.disabled = true;
    loadWasm();
});

console.log('JavaScript loaded');
