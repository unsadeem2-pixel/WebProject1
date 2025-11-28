
// ALL TOOL DEFINITIONS 
const toolDefinitions = {
    password: {
        title: 'Password Strength Checker',
        definition: 'Analyzes the entered password based on length, complexity, and common patterns.'
    },
    url: {
        title: 'URL Analyzer',
        definition: 'Checks a link for protocol, domain legitimacy, and suspicious indicators.'
    },
    file: {
        title: 'File Name Analyzer',
        definition: 'Detects misleading file names and dangerous dual extensions such as .pdf.exe.'
    },
    vpn: {
        title: 'Virtual Private Network (VPN)',
        definition: 'Encrypts your internet traffic and hides your real IP address, providing safer browsing—especially on public Wi-Fi networks.'
    },
    authenticator: {
        title: 'Two-Factor Authentication (2FA)',
        definition: 'Creates short-lived verification codes that act as an extra security layer to confirm your identity when logging in.'
    },
    encryption: {
        title: 'Full Disk Encryption (FDE)',
        definition: ' Protects all data on your device by encrypting it entirely, preventing unauthorized access if the device is lost or stolen.'
    },
    cleaner: {
        title: 'System Cleaner',
        definition: 'Cleans temporary files, cached data, and leftover malware traces to improve system performance and stability.'
    }
};

// SCENARIO DATA & HINTS 
const scenarioData = {
    'scenario-1': { // Public Wi-Fi Security
        correctAnswer: 'vpn',
        hint: 'Someone could intercept your connection. Encryption during transit is the key.'
    },
    'scenario-2': { // Protecting Your Main Login
        correctAnswer: 'authenticator',
        hint: 'The code changes frequently to stop attackers from accessing your account remotely.'
    },
    'scenario-3': { // Cleaning System Traces
        correctAnswer: 'cleaner',
        hint: 'The goal is to remove leftover files and clutter to keep your system clean and running smoothly.'
    }
};


//MAIN TOOL FUNCTIONS (For the top 3 cards)


// 1 Password Strength Checker
function checkPasswordStrength() {
    const password = document.getElementById('passwordInput').value;
    const resultElement = document.getElementById('passwordResult');
    
    let score = 0;
    
    // Check length (10 chars minimum requirement)
    if (password.length >= 10) { score += 1; }
    // Check complexity
    if (/[A-Z]/.test(password)) { score += 1; } // Uppercase
    if (/[a-z]/.test(password)) { score += 1; } // Lowercase
    if (/\d/.test(password)) { score += 1; } // Numbers
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) { score += 1; } // Symbols

    resultElement.className = 'tool-result'; // Reset classes

    if (password.length < 1) {
        resultElement.textContent = 'Result: Awaiting input...';
    } else if (score >= 4 && password.length >= 10) {
        resultElement.textContent = 'Result: Excellent! Secure.';
        resultElement.classList.add('safe');
    } else if (score >= 3) {
        resultElement.textContent = 'Result: Good, but could be stronger.';
        resultElement.classList.add('warning');
    } else {
        resultElement.textContent = 'Result: Weak. Increase length and complexity.';
        resultElement.classList.add('danger');
    }
}

// 2 URL Analyzer
function analyzeUrl() {
    const url = document.getElementById('urlInput').value.trim();
    const resultElement = document.getElementById('urlResult');
    resultElement.className = 'tool-result'; // Reset classes

    if (url === "") {
        resultElement.textContent = 'Result: Awaiting input...';
        return;
    }

    const isSecureProtocol = url.startsWith('https://');
    // Look for common phishing/suspicious indicators in the domain/subdomain
    const suspiciousKeywords = /(login|verify|update|bank|secure|account)/i;
    const isSuspicious = suspiciousKeywords.test(url.replace(/https?:\/\//i, ''));
    
    if (isSuspicious) {
        resultElement.textContent = 'Result: Danger! Contains suspicious keywords. Exercise extreme caution.';
        resultElement.classList.add('danger');
    } else if (!isSecureProtocol) {
        resultElement.textContent = 'Result: Warning! Protocol is insecure (HTTP).';
        resultElement.classList.add('warning');
    } else {
        resultElement.textContent = 'Result: Safe. HTTPS protocol detected.';
        resultElement.classList.add('safe');
    }
}

// 3 File Name Analyzer
function analyzeFileName() {
    const fileName = document.getElementById('fileNameInput').value.trim();
    const resultElement = document.getElementById('fileNameResult');
    resultElement.className = 'tool-result'; // Reset classes
    
    if (fileName === "") {
        resultElement.textContent = 'Result: Awaiting input...';
        return;
    }
    
    // Regex for dual extension (e.g., .doc.exe, .pdf.scr)
    const dualExtensionRegex = /\.(pdf|jpg|gif|doc|txt)\.(exe|bat|cmd|scr|vbs|js)$/i;
    // Regex for general dangerous executable files
    const dangerousExecutableRegex = /\.(exe|bat|cmd|scr|vbs|js)$/i;
    
    if (dualExtensionRegex.test(fileName)) {
        resultElement.textContent = 'Result: Danger! Malicious dual extension detected (.EXE hidden).';
        resultElement.classList.add('danger');
    } else if (dangerousExecutableRegex.test(fileName)) {
        resultElement.textContent = 'Result: Warning! Executable file (.EXE). Verify sender before opening.';
        resultElement.classList.add('warning');
    } else {
        resultElement.textContent = 'Result: Safe. Standard file extension detected.';
        resultElement.classList.add('safe');
    }
}

//SCENARIO CHALLENGE FUNCTIONS


// 2.1 Check Scenario Answer and Show Tool Definition Modal
function checkScenario(scenarioId, selectedTool) {
    const resultElement = document.getElementById(`${scenarioId}-result`);
    const data = scenarioData[scenarioId];
    
    // 1. Get tool details for modal (using the selectedTool key from scenarioData)
    const toolDetails = toolDefinitions[selectedTool];
    showModal(toolDetails.title, toolDetails.definition);

    // 2. Check the answer
    resultElement.className = 'result-display';
    
    if (selectedTool === data.correctAnswer) {
        resultElement.textContent = 'CORRECT! This is the most effective tool for this threat.';
        resultElement.classList.add('safe');
    } else {
        resultElement.textContent = 'INCORRECT. Review the threat and try a different tool.';
        resultElement.classList.add('danger');
    }
}

// 2.2 Display the Hint
function showHint(scenarioId) {
    const data = scenarioData[scenarioId];
    const hintOutputElement = document.getElementById(`${scenarioId}-hint-output`);
    
    // Prevent hint duplication
    if (hintOutputElement.textContent !== '') return; 
    
    hintOutputElement.textContent = data.hint;
}



//MODAL FUNCTIONALITY (Pop-up Window)


// 3.1 Function to open the Modal
function showModal(title, definition) {
    const modal = document.getElementById('toolModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalDefinition = document.getElementById('modalDefinition');
    
    modalTitle.textContent = title;
    modalDefinition.textContent = definition;
    
    modal.style.display = 'block';
}

function closeModal() {
    document.getElementById('toolModal').style.display = 'none';
}

// Close the Modal when clicking outside of it (Event Delegation)
window.onclick = function(event) {
    const modal = document.getElementById('toolModal');
    if (event.target === modal) {
        modal.style.display = "none";
    }
}

function navigateToHome(event) {
    // منع السلوك الافتراضي للرابط (التنقل الفوري)
    event.preventDefault(); 
    
    // 1. إغلاق الـ Modal لضمان عدم التداخل
    closeModal(); 

    // 2. الانتقال إلى الصفحة الرئيسية بعد إغلاق المودال
    window.location.href = 'index.html';
}