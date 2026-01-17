
// ==================== INITIALIZATION ====================

// Socket.IO connection
const socket = io.connect(window.location.origin, {
  transports: ['websocket', 'polling'],
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionAttempts: 5
});

// Active downloads tracking
const activeDownloads = {};

// DOM Elements
const urlInput = document.getElementById('urlInput');
const formatSelect = document.getElementById('formatSelect');
const qualitySelect = document.getElementById('qualitySelect');
const pathInput = document.getElementById('pathInput');
const pathStatus = document.getElementById('pathStatus');
const validatePathBtn = document.getElementById('validatePath');
const modeToggle = document.getElementById('modeToggle');
const urlCount = document.getElementById('urlCount');
const activeDownloadsContainer = document.getElementById('activeDownloads');
const historyList = document.getElementById('historyList');
const searchHistory = document.getElementById('searchHistory');
const refreshHistoryBtn = document.getElementById('refreshHistoryBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const historySection = document.getElementById('historySection');
const guestMessage = document.getElementById('guestMessage');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const userInfo = document.getElementById('userInfo');
const userName = document.getElementById('userName');
const globalSpinner = document.getElementById('globalSpinner');
const downloadBtn = document.getElementById('downloadBtn');
const loadingScreen = document.getElementById('loadingScreen');
const toastContainer = document.getElementById('toastContainer');
const pathGroup = document.getElementById('pathGroup');

// Auth0 Client
let auth0Client = null;
const auth0Domain = 'dev-vf7yc5q2gluzl6by.us.auth0.com';
const auth0ClientId = 'ZHKFohhXeeDFTmmXoxhTOyQJMKJFAB5U';
const auth0Audience = 'https://justpaste/api';

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', async () => {
  try {
    await initAuth0();
    await loadHistory();
    setupEventListeners();
    setupSocketListeners();
    updateQualityOptions();
    handleMobileDetection();
    initThreeJS();
    initAnimations();
    loadThemePreference();
    
    // Hide loading screen
    setTimeout(() => {
      loadingScreen.style.opacity = '0';
      setTimeout(() => {
        loadingScreen.style.display = 'none';
      }, 500);
    }, 1000);
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  } catch (error) {
    console.error('Initialization error:', error);
    showToast('Error', 'Failed to initialize application', 'error');
  }
});

// ==================== AUTH0 ====================

async function initAuth0() {
  try {
    auth0Client = await auth0.createAuth0Client({
      domain: auth0Domain,
      clientId: auth0ClientId,
      authorizationParams: {
        redirect_uri: window.location.origin,
        audience: auth0Audience,
        scope: 'openid profile email read:history write:history'
      },
      cacheLocation: 'localstorage',
      useRefreshTokens: true
    });

    // Handle callback
    if (window.location.search.includes('code=') && window.location.search.includes('state=')) {
      await auth0Client.handleRedirectCallback();
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    await updateAuthUI();
  } catch (err) {
    console.error('Auth0 initialization error:', err);
    showToast('Authentication Error', err.message, 'error');
  }
}

async function updateAuthUI() {
  try {
    const isAuthenticated = await auth0Client.isAuthenticated();
    
    if (isAuthenticated) {
      const user = await auth0Client.getUser();
      userName.textContent = user.name || user.email || 'User';
      loginBtn.style.display = 'none';
      logoutBtn.style.display = 'inline-flex';
      userInfo.style.display = 'flex';
      historySection.style.display = 'block';
      guestMessage.style.display = 'none';
      await loadHistory();
    } else {
      loginBtn.style.display = 'inline-flex';
      logoutBtn.style.display = 'none';
      userInfo.style.display = 'none';
      historySection.style.display = 'none';
      guestMessage.style.display = 'block';
    }
  } catch (err) {
    console.error('Auth UI update error:', err);
  }
}

async function login() {
  try {
    await auth0Client.loginWithRedirect();
  } catch (err) {
    console.error('Login error:', err);
    showToast('Login Error', err.message, 'error');
  }
}

async function logout() {
  try {
    await auth0Client.logout({
      logoutParams: {
        returnTo: window.location.origin
      }
    });
  } catch (err) {
    console.error('Logout error:', err);
    showToast('Logout Error', err.message, 'error');
  }
}

// ==================== DEVICE DETECTION ====================

function handleMobileDetection() {
  if (isMobile()) {
    pathGroup.style.display = 'none';
  }
}

function isMobile() {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

// ==================== EVENT LISTENERS ====================

function setupEventListeners() {
  urlInput.addEventListener('input', debounce(updateURLCount, 300));
  formatSelect.addEventListener('change', updateQualityOptions);
  downloadBtn.addEventListener('click', startDownload);
  validatePathBtn.addEventListener('click', validatePath);
  modeToggle.addEventListener('click', toggleTheme);
  refreshHistoryBtn.addEventListener('click', loadHistory);
  clearHistoryBtn.addEventListener('click', clearHistory);
  searchHistory.addEventListener('input', debounce(filterHistory, 300));
  loginBtn.addEventListener('click', login);
  logoutBtn.addEventListener('click', logout);
  
  // Enter key to start download
  urlInput.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
      startDownload();
    }
  });
}

// Debounce utility
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// ==================== SOCKET.IO LISTENERS ====================

function setupSocketListeners() {
  socket.on('connect', () => {
    console.log('Socket.IO connected');
  });
  
  socket.on('disconnect', () => {
    console.log('Socket.IO disconnected');
    showToast('Connection Lost', 'Reconnecting...', 'error');
  });
  
  socket.on('connect_error', (error) => {
    console.error('Socket.IO connection error:', error);
  });
  
  socket.on('download_progress', (data) => {
    updateDownloadProgress(data);
  });
  
  socket.on('download_complete', (data) => {
    completeDownload(data);
    loadHistory();
  });
  
  socket.on('download_error', (data) => {
    showDownloadError(data);
  });
}

// ==================== URL COUNT ====================

function updateURLCount() {
  const urls = urlInput.value.split('\n').filter(url => url.trim());
  urlCount.textContent = urls.length;
  
  // Visual feedback
  if (urls.length > 0) {
    urlInput.style.borderColor = 'var(--primary)';
  } else {
    urlInput.style.borderColor = 'var(--border-color)';
  }
}

// ==================== QUALITY OPTIONS ====================

function updateQualityOptions() {
  const format = formatSelect.value;
  qualitySelect.innerHTML = '';
  
  if (format === 'mp4') {
    qualitySelect.innerHTML = `
      <option value="2160p">4K (2160p)</option>
      <option value="1440p">2K (1440p)</option>
      <option value="1080p" selected>Full HD (1080p)</option>
      <option value="720p">HD (720p)</option>
      <option value="480p">SD (480p)</option>
      <option value="360p">Low (360p)</option>
      <option value="best">Best Available</option>
    `;
  } else if (format === 'mp3' || format === 'wav') {
    qualitySelect.innerHTML = `
      <option value="320kbps">320 kbps (Best)</option>
      <option value="256kbps">256 kbps</option>
      <option value="192kbps" selected>192 kbps</option>
      <option value="128kbps">128 kbps</option>
      <option value="best">Best Available</option>
    `;
  } else {
    qualitySelect.innerHTML = `<option value="best">Best Available</option>`;
  }
}

// ==================== PATH VALIDATION ====================

async function validatePath() {
  const path = pathInput.value.trim();
  
  if (!path) {
    showPathStatus('Please enter a path', 'invalid');
    return;
  }
  
  validatePathBtn.disabled = true;
  validatePathBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
  
  try {
    const response = await fetch('/validate_path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path })
    });
    
    const data = await response.json();
    
    if (data.valid) {
      showPathStatus('✓ ' + data.message, 'valid');
    } else {
      showPathStatus('✗ ' + data.message, 'invalid');
    }
  } catch (error) {
    showPathStatus('✗ Error validating path', 'invalid');
  } finally {
    validatePathBtn.disabled = false;
    validatePathBtn.innerHTML = '<i class="fas fa-check-circle"></i>';
  }
}

function showPathStatus(message, type) {
  pathStatus.textContent = message;
  pathStatus.className = `path-status ${type}`;
}

// ==================== SECURE DOWNLOAD HANDLING ====================

let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 6000; // 6 seconds between downloads

function checkRateLimit() {
  const now = Date.now();
  if (now - lastRequestTime < MIN_REQUEST_INTERVAL) {
    const waitTime = Math.ceil((MIN_REQUEST_INTERVAL - (now - lastRequestTime)) / 1000);
    showToast('Rate Limit', `Please wait ${waitTime} seconds before downloading again`, 'warning');
    return false;
  }
  lastRequestTime = now;
  return true;
}

async function startDownload() {
  if (!checkRateLimit()) {
    return;
  }

  const urls = urlInput.value.split('\n').filter(url => url.trim());
  const format = formatSelect.value;
  const quality = qualitySelect.value;
  let path = pathInput.value.trim();
 
  if (isMobile()) {
    path = '';
  }
 
  if (urls.length === 0) {
    showToast('Error', 'Please enter at least one URL', 'error');
    return;
  }
 
  if (urls.length > 10) {
    showToast('Error', 'Maximum 10 URLs allowed at once', 'error');
    return;
  }
 
  // Validate URLs client-side
  const invalidUrls = urls.filter(url => !isValidURL(url.trim()));
  if (invalidUrls.length > 0) {
    showToast('Error', `${invalidUrls.length} invalid URL(s) detected`, 'error');
    return;
  }
 
  downloadBtn.disabled = true;
  downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Starting...</span>';
 
  clearActiveDownloads();
 
  urls.forEach((url, index) => {
    const downloadId = `download_${index}_${Date.now()}`;
    createDownloadItem(downloadId, url, format, quality);
    activeDownloads[downloadId] = { url, format, quality };
  });
 
  try {
    let headers = { 'Content-Type': 'application/json' };
   
    // Add auth token if logged in
    if (await auth0Client.isAuthenticated()) {
      const token = await auth0Client.getTokenSilently();
      headers['Authorization'] = `Bearer ${token}`;
    }
   
    const response = await fetch('/download', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        urls,
        format,
        quality,
        path
      })
    });
   
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }
   
    const data = await response.json();
   
    if (data.success) {
      showToast('Success', `Downloaded ${data.results.length} file(s)`, 'success');
     
      // Handle download with secure token
      if (data.download_url) {
        // For authenticated users with download tokens
        window.location.href = data.download_url;
      } else if (data.path) {
        showToast('Saved', `Files saved to ${data.path}`, 'info');
      }
     
      urlInput.value = '';
      updateURLCount();
     
      await loadHistory();
    } else {
      const errorMsg = data.errors?.map(e => e.error).join(', ') || 'Unknown error';
      showToast('Download Failed', errorMsg, 'error');
    }
   
  } catch (error) {
    console.error('Download error:', error);
    showToast('Error', error.message || 'Download failed', 'error');
  } finally {
    downloadBtn.disabled = false;
    downloadBtn.innerHTML = '<i class="fas fa-download"></i> <span>Start Download</span>';
  }
}

function clearActiveDownloads() {
  activeDownloadsContainer.innerHTML = '';
  Object.keys(activeDownloads).forEach(key => delete activeDownloads[key]);
}

function createDownloadItem(downloadId, url, format, quality) {
  const item = document.createElement('div');
  item.className = 'download-item';
  item.id = downloadId;
  
  let displayUrl = url;
  try {
    const urlObj = new URL(url);
    displayUrl = urlObj.hostname;
  } catch (e) {
    displayUrl = url.substring(0, 50) + '...';
  }
  
  item.innerHTML = `
    <div class="download-header">
      <div class="download-title" title="${url}">${displayUrl}</div>
      <div class="download-status">Initializing...</div>
    </div>
    <div class="progress-bar-container">
      <div class="progress-bar-fill" style="width: 0%"></div>
    </div>
    <div class="download-info">
      <div class="info-item">
        <span class="info-label">Progress</span>
        <span class="info-value progress-text">0%</span>
      </div>
      <div class="info-item">
        <span class="info-label">Speed</span>
        <span class="info-value speed-text">-</span>
      </div>
      <div class="info-item">
        <span class="info-label">ETA</span>
        <span class="info-value eta-text">-</span>
      </div>
      <div class="info-item">
        <span class="info-label">Downloaded</span>
        <span class="info-value downloaded-text">0 B / Unknown</span>
      </div>
    </div>
  `;
  
  activeDownloadsContainer.appendChild(item);
  gsap.from(item, {opacity: 0, y: 20, duration: 0.5, ease: 'power2.out'});
}

function updateDownloadProgress(data) {
  const item = document.getElementById(data.download_id);
  if (!item) return;
  
  const progressBar = item.querySelector('.progress-bar-fill');
  const progressText = item.querySelector('.progress-text');
  const speedText = item.querySelector('.speed-text');
  const etaText = item.querySelector('.eta-text');
  const downloadedText = item.querySelector('.downloaded-text');
  const statusBadge = item.querySelector('.download-status');
  
  const percentNum = parseFloat(data.percent) || 0;
  progressBar.style.width = `${percentNum}%`;
  progressText.textContent = data.percent;
  speedText.textContent = data.speed || '-';
  etaText.textContent = data.eta || '-';
  downloadedText.textContent = `${data.downloaded || '0 B'} / ${data.total || 'Unknown'}`;
  statusBadge.textContent = data.status || 'Downloading...';
}

function completeDownload(data) {
  const item = document.getElementById(data.download_id);
  if (!item) return;
 
  const progressBar = item.querySelector('.progress-bar-fill');
  const progressText = item.querySelector('.progress-text');
  const statusBadge = item.querySelector('.download-status');
  const downloadTitle = item.querySelector('.download-title');
 
  progressBar.style.width = '100%';
  progressText.textContent = '100%';
  statusBadge.textContent = 'Complete';
  statusBadge.style.background = 'var(--secondary)';
  downloadTitle.textContent = data.title || 'Download Complete';
 
  gsap.to(item, {
    background: 'rgba(34, 197, 94, 0.1)',
    duration: 0.5,
    onComplete: () => {
      setTimeout(() => {
        gsap.to(item, {
          opacity: 0,
          height: 0,
          marginBottom: 0,
          padding: 0,
          duration: 0.3,
          onComplete: () => item.remove()
        });
      }, 5000);
    }
  });
}

function showDownloadError(data) {
  const item = document.getElementById(data.download_id);
  if (!item) return;
  
  const statusBadge = item.querySelector('.download-status');
  statusBadge.textContent = 'Error';
  statusBadge.style.background = 'var(--danger)';
  
  gsap.to(item, {background: 'rgba(239, 68, 68, 0.1)', duration: 0.5});
  
  showToast('Download Error', data.error || 'Unknown error', 'error');
  
  setTimeout(() => {
    gsap.to(item, {
      opacity: 0, 
      height: 0,
      marginBottom: 0,
      padding: 0,
      duration: 0.5, 
      onComplete: () => item.remove()
    });
  }, 5000);
}

// ==================== HISTORY ====================

async function loadHistory() {
  if (!auth0Client || !(await auth0Client.isAuthenticated())) {
    return;
  }
  
  showSpinner();
  showSkeleton(5);
  
  try {
    const token = await auth0Client.getTokenSilently();
    const response = await fetch('/history', {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to load history');
    }
    
    const data = await response.json();
    
    historyList.innerHTML = '';
    
    if (data.length === 0) {
      historyList.innerHTML = `
        <div class="no-downloads">
          <i class="fas fa-history"></i>
          <p>No download history yet</p>
        </div>
      `;
      return;
    }
    
    data.forEach((item, index) => {
      const historyItem = createHistoryItem(item);
      historyList.appendChild(historyItem);
      gsap.from(historyItem, {
        opacity: 0, 
        y: 20, 
        duration: 0.4, 
        delay: index * 0.05,
        ease: 'power2.out'
      });
    });
  } catch (error) {
    console.error('Error loading history:', error);
    historyList.innerHTML = `
      <div class="no-downloads">
        <i class="fas fa-exclamation-circle"></i>
        <p>Error loading history</p>
      </div>
    `;
    showToast('Error', 'Failed to load history', 'error');
  } finally {
    hideSpinner();
  }
}

function showSpinner() {
  globalSpinner.style.display = 'flex';
}

function hideSpinner() {
  globalSpinner.style.display = 'none';
}

function showSkeleton(count) {
  historyList.innerHTML = '';
  for (let i = 0; i < count; i++) {
    const skeleton = document.createElement('div');
    skeleton.className = 'skeleton-item';
    historyList.appendChild(skeleton);
  }
}

function createHistoryItem(item) {
  const div = document.createElement('div');
  div.className = 'history-item';
  div.dataset.id = item.id;
 
  const date = new Date(item.timestamp);
  const formattedDate = date.toLocaleString();
 
  // Create download button HTML only if token exists
  const downloadButton = item.download_token ?
    `<button class="icon-btn" onclick="downloadHistoryFile('${item.download_token}')" title="Download Again">
      <i class="fas fa-download"></i>
    </button>` : '';
 
  div.innerHTML = `
    <div class="history-info">
      <div class="history-title" title="${escapeHtml(item.title || 'Unknown Title')}">${escapeHtml(item.title || 'Unknown Title')}</div>
      <div class="history-meta">
        <span><i class="fas fa-calendar"></i> ${formattedDate}</span>
        <span><i class="fas fa-file"></i> ${item.file_format.toUpperCase()}</span>
        <span><i class="fas fa-signal"></i> ${item.quality || 'N/A'}</span>
        <span><i class="fas fa-hdd"></i> ${item.file_size || 'N/A'}</span>
      </div>
    </div>
    <div class="history-actions">
      ${downloadButton}
      <button class="icon-btn" onclick="copyUrl('${escapeHtml(item.url)}')" title="Copy URL">
        <i class="fas fa-link"></i>
      </button>
      <button class="icon-btn delete" onclick="deleteHistoryItem(${item.id})" title="Delete">
        <i class="fas fa-trash-alt"></i>
      </button>
    </div>
  `;
 
  return div;
}

function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

window.copyUrl = function(url) {
  if (!url) return;
  navigator.clipboard.writeText(url).then(() => {
    showToast('Copied', 'URL copied to clipboard', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showToast('Error', 'Failed to copy URL', 'error');
  });
};

window.copyPath = function(path) {
  if (!path) return;
  navigator.clipboard.writeText(path).then(() => {
    showToast('Copied', 'Path copied to clipboard', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showToast('Error', 'Failed to copy path', 'error');
  });
};

window.deleteHistoryItem = async function(id) {
  if (!confirm('Delete this history item?')) return;
  
  try {
    const token = await auth0Client.getTokenSilently();
    const response = await fetch(`/delete_history/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    
    if (response.ok) {
      const item = document.querySelector(`[data-id="${id}"]`);
      if (item) {
        gsap.to(item, {
          opacity: 0,
          x: -50,
          height: 0,
          marginBottom: 0,
          padding: 0,
          duration: 0.3,
          onComplete: () => {
            item.remove();
            if (historyList.children.length === 0) {
              loadHistory();
            }
          }
        });
      }
      showToast('Deleted', 'History item deleted', 'success');
    } else {
      throw new Error('Failed to delete');
    }
  } catch (error) {
    console.error('Error deleting history item:', error);
    showToast('Error', 'Failed to delete item', 'error');
  }
};

window.downloadHistoryFile = async function(token) {
  try {
    if (!token) {
      showToast('Error', 'Download token missing', 'error');
      return;
    }
   
    // Get auth token
    const authToken = await auth0Client.getTokenSilently();
   
    // Create download URL with secure token
    const downloadUrl = `/download_file?token=${token}`;
   
    // Trigger download with authentication
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
   
    showToast('Download Started', 'Your file is being downloaded', 'success');
   
  } catch (error) {
    console.error('Download error:', error);
    showToast('Error', 'Failed to download file', 'error');
  }
};

async function clearHistory() {
  if (!confirm('Clear all download history? This cannot be undone.')) return;
  
  showSpinner();
  
  try {
    const token = await auth0Client.getTokenSilently();
    const response = await fetch('/clear_history', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` }
    });
    
    if (response.ok) {
      await loadHistory();
      showToast('Cleared', 'Download history cleared', 'success');
    } else {
      throw new Error('Failed to clear history');
    }
  } catch (error) {
    console.error('Error clearing history:', error);
    showToast('Error', 'Failed to clear history', 'error');
  } finally {
    hideSpinner();
  }
}

function filterHistory() {
  const searchTerm = searchHistory.value.toLowerCase();
  const items = document.querySelectorAll('.history-item');
  
  items.forEach(item => {
    const text = item.textContent.toLowerCase();
    if (text.includes(searchTerm)) {
      item.style.display = '';
      gsap.to(item, {opacity: 1, duration: 0.3});
    } else {
      gsap.to(item, {
        opacity: 0, 
        duration: 0.3,
        onComplete: () => {
          item.style.display = 'none';
        }
      });
    }
  });
}

// ==================== ENHANCED URL VALIDATION ====================

function isValidURL(string) {
  try {
    const url = new URL(string);
   
    // Must be http or https
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }
   
    // Block localhost and private IPs
    const hostname = url.hostname.toLowerCase();
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
   
    if (blockedHosts.includes(hostname)) {
      return false;
    }
   
    // Block private IP ranges
    if (hostname.startsWith('10.') ||
        hostname.startsWith('172.16.') ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('169.254.')) {
      return false;
    }
   
    return true;
  } catch (_) {
    return false;
  }
}

// ==================== THEME ====================

function toggleTheme() {
  document.body.classList.toggle('light-mode');
  const icon = modeToggle.querySelector('i');
  
  if (document.body.classList.contains('light-mode')) {
    icon.className = 'fas fa-sun';
    localStorage.setItem('theme', 'light');
  } else {
    icon.className = 'fas fa-moon';
    localStorage.setItem('theme', 'dark');
  }
  
  gsap.from('body', {opacity: 0.8, duration: 0.3});
}

function loadThemePreference() {
  const theme = localStorage.getItem('theme');
  const icon = modeToggle.querySelector('i');
  
  if (theme === 'light') {
    document.body.classList.add('light-mode');
    icon.className = 'fas fa-sun';
  } else {
    icon.className = 'fas fa-moon';
  }
}

// ==================== TOAST NOTIFICATIONS ====================

function showToast(title, message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  const icons = {
    success: 'fa-check-circle',
    error: 'fa-exclamation-circle',
    info: 'fa-info-circle',
    warning: 'fa-exclamation-triangle'
  };
  
  toast.innerHTML = `
    <div class="toast-header">
      <i class="fas ${icons[type] || icons.info}"></i>
      <span>${title}</span>
    </div>
    <div class="toast-body">${message}</div>
  `;
  
  toastContainer.appendChild(toast);
  
  gsap.from(toast, {x: 400, opacity: 0, duration: 0.3, ease: 'power2.out'});
  
  setTimeout(() => {
    gsap.to(toast, {
      x: 400,
      opacity: 0,
      duration: 0.3,
      ease: 'power2.in',
      onComplete: () => toast.remove()
    });
  }, 5000);
  
  // Browser notification
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification(title, {
      body: message,
      icon: '/static/assets/imgs/logo.jpg'
    });
  }
}

// ==================== THREE.JS BACKGROUND ====================

function initThreeJS() {
  const container = document.getElementById('threejs-bg');
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
  
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setPixelRatio(window.devicePixelRatio);
  container.appendChild(renderer.domElement);
  
  // Create particles
  const particlesGeometry = new THREE.BufferGeometry();
  const particlesCount = 1000;
  const posArray = new Float32Array(particlesCount * 3);
  
  for (let i = 0; i < particlesCount * 3; i++) {
    posArray[i] = (Math.random() - 0.5) * 100;
  }
  
  particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
  
  const particlesMaterial = new THREE.PointsMaterial({
    size: 0.05,
    color: 0x0D6EFD,
    transparent: true,
    opacity: 0.8
  });
  
  const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
  scene.add(particlesMesh);
  
  camera.position.z = 30;
  
  // Animation
  let mouseX = 0;
  let mouseY = 0;
  
  document.addEventListener('mousemove', (event) => {
    mouseX = (event.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
  });
  
  function animate() {
    requestAnimationFrame(animate);
    
    particlesMesh.rotation.y += 0.0005;
    particlesMesh.rotation.x += 0.0003;
    
    camera.position.x += (mouseX * 2 - camera.position.x) * 0.05;
    camera.position.y += (mouseY * 2 - camera.position.y) * 0.05;
    camera.lookAt(scene.position);
    
    renderer.render(scene, camera);
  }
  
  animate();
  
  // Handle resize
  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });
}

// ==================== GSAP ANIMATIONS ====================

function initAnimations() {
  gsap.registerPlugin(ScrollTrigger);
  
  // Header animation
  gsap.from('header', {
    opacity: 0,
    y: -50,
    duration: 1,
    ease: 'power3.out'
  });
  
  // Cards animation
  gsap.utils.toArray('.card').forEach((card, index) => {
    gsap.from(card, {
      scrollTrigger: {
        trigger: card,
        start: 'top 80%',
        toggleActions: 'play none none reverse'
      },
      opacity: 0,
      y: 50,
      duration: 0.8,
      delay: index * 0.1,
      ease: 'power2.out'
    });
  });
  
  // Features animation
  gsap.utils.toArray('.feature-item').forEach((item, index) => {
    gsap.from(item, {
      scrollTrigger: {
        trigger: item,
        start: 'top 85%',
        toggleActions: 'play none none reverse'
      },
      opacity: 0,
      scale: 0.8,
      duration: 0.5,
      delay: index * 0.05,
      ease: 'back.out(1.7)'
    });
  });
  
  // Platform badges animation
  gsap.utils.toArray('.platform-badge').forEach((badge, index) => {
    gsap.from(badge, {
      scrollTrigger: {
        trigger: badge,
        start: 'top 90%',
        toggleActions: 'play none none reverse'
      },
      opacity: 0,
      y: 30,
      duration: 0.4,
      delay: index * 0.03,
      ease: 'power2.out'
    });
  });
  
  // Footer animation
  gsap.from('footer', {
    scrollTrigger: {
      trigger: 'footer',
      start: 'top 90%',
      toggleActions: 'play none none reverse'
    },
    opacity: 0,
    y: 50,
    duration: 0.8,
    ease: 'power2.out'
  });
}

// ==================== UTILITY FUNCTIONS ====================

// Format bytes to human readable
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Format duration
function formatDuration(seconds) {
  if (!seconds || isNaN(seconds)) return 'N/A';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  }
  return `${m}:${s.toString().padStart(2, '0')}`;
}

// ==================== ERROR HANDLING ====================

window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
  showToast('Error', 'An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  showToast('Error', 'An unexpected error occurred', 'error');
});

// ==================== SERVICE WORKER (Optional) ====================

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    // Uncomment to enable service worker
    // navigator.serviceWorker.register('/sw.js')
    //   .then(registration => console.log('SW registered:', registration))
    //   .catch(error => console.log('SW registration failed:', error));
  });
}

// ==================== KEYBOARD SHORTCUTS ====================

document.addEventListener('keydown', (e) => {
  // Ctrl/Cmd + K to focus URL input
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    urlInput.focus();
  }
  
  // Ctrl/Cmd + Enter to start download
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (urlInput.value.trim() && !downloadBtn.disabled) {
      startDownload();
    }
  }
  
  // Escape to clear active downloads
  if (e.key === 'Escape' && activeDownloadsContainer.children.length > 0) {
    if (confirm('Cancel all active downloads?')) {
      clearActiveDownloads();
    }
  }
});

// ==================== VISIBILITY CHANGE ====================

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    console.log('Page hidden');
  } else {
    console.log('Page visible');
    // Refresh data when page becomes visible
    if (auth0Client) {
      updateAuthUI();
    }
  }
});

// ==================== ONLINE/OFFLINE ====================

window.addEventListener('online', () => {
  showToast('Connected', 'Internet connection restored', 'success');
});

window.addEventListener('offline', () => {
  showToast('Offline', 'No internet connection', 'error');
});

// ==================== PASTE EVENT ====================

urlInput.addEventListener('paste', (e) => {
  setTimeout(() => {
    updateURLCount();
    
    // Auto-validate URLs
    const urls = urlInput.value.split('\n').filter(url => url.trim());
    const invalidUrls = urls.filter(url => !isValidURL(url.trim()));
    
    if (invalidUrls.length > 0) {
      showToast('Warning', `${invalidUrls.length} invalid URL(s) detected`, 'warning');
    }
  }, 100);
});

// ==================== DRAG AND DROP ====================

urlInput.addEventListener('dragover', (e) => {
  e.preventDefault();
  urlInput.style.borderColor = 'var(--primary)';
  urlInput.style.background = 'rgba(13, 110, 253, 0.1)';
});

urlInput.addEventListener('dragleave', (e) => {
  e.preventDefault();
  urlInput.style.borderColor = 'var(--border-color)';
  urlInput.style.background = 'rgba(255, 255, 255, 0.03)';
});

urlInput.addEventListener('drop', (e) => {
  e.preventDefault();
  urlInput.style.borderColor = 'var(--border-color)';
  urlInput.style.background = 'rgba(255, 255, 255, 0.03)';
  
  const text = e.dataTransfer.getData('text');
  if (text) {
    const currentValue = urlInput.value.trim();
    urlInput.value = currentValue ? currentValue + '\n' + text : text;
    updateURLCount();
  }
});

// ==================== CONSOLE WELCOME MESSAGE ====================

console.log('%c🚀 Just Paste Downloader v1.2', 'font-size: 20px; font-weight: bold; color: #0D6EFD;');
console.log('%cDeveloped with ❤️ by Codify', 'font-size: 14px; color: #22C55E;');
console.log('%cKeyboard Shortcuts:', 'font-size: 14px; font-weight: bold; color: #8B5CF6;');
console.log('%c  • Ctrl/Cmd + K: Focus URL input', 'font-size: 12px;');
console.log('%c  • Ctrl/Cmd + Enter: Start download', 'font-size: 12px;');
console.log('%c  • Escape: Cancel active downloads', 'font-size: 12px;');

console.log('🔒 Secure download handlers loaded');
console.log('✅ Rate limiting enabled');
console.log('✅ URL validation enabled');
console.log('✅ Token-based downloads enabled');

// ==================== EXPORT FOR DEBUGGING ====================

if (typeof window !== 'undefined') {
  window.justPasteDebug = {
    auth0Client,
    activeDownloads,
    loadHistory,
    showToast,
    clearActiveDownloads
  };
}