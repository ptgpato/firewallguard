document.addEventListener('DOMContentLoaded', () => {
  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(element => {
      bootstrap.Tooltip.getOrCreateInstance(element);
    });
  }

  const timeDisplay = document.getElementById('system-clock');
  if (timeDisplay) {
    const updateClock = () => {
      const now = new Date();
      timeDisplay.textContent = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    };
    updateClock();
    setInterval(updateClock, 1000);
  }

  const sidebar = document.getElementById('sidebar');
  const sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebar && sidebarToggle) {
    sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('show'));
    sidebar.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => sidebar.classList.remove('show'));
    });
  }
});

const originalFetch = window.fetch;
window.fetch = (input, init = {}) => {
  const requestUrl = typeof input === 'string' ? input : input.url;
  const isSameOrigin = new URL(requestUrl, window.location.origin).origin === window.location.origin;
  const method = (init.method || (typeof input !== 'string' ? input.method : 'GET')).toUpperCase();

  if (isSameOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
    const token = document.querySelector('meta[name="csrf-token"]')?.content;
    if (token) headers.set('X-CSRFToken', token);
    init = { ...init, headers };
  }

  return originalFetch(input, init);
};

function showToast(title, message, type = 'success') {
  const toastContainer = document.getElementById('toastContainer');
  if (!toastContainer || !window.bootstrap) return;

  const bgBorderClass = type === 'success' ? 'border-success' : type === 'danger' ? 'border-danger' : 'border-info';
  const icon = type === 'success' ? 'bi-check-circle-fill text-success' : type === 'danger' ? 'bi-exclamation-triangle-fill text-danger' : 'bi-info-circle-fill text-cyan';

  const toastEl = document.createElement('div');
  toastEl.className = `toast align-items-center mb-2 ${bgBorderClass}`;
  toastEl.setAttribute('role', 'alert');
  toastEl.setAttribute('aria-live', 'assertive');
  toastEl.setAttribute('aria-atomic', 'true');
  toastEl.dataset.bsDelay = '4000';
  toastEl.innerHTML = `
    <div class="toast-header bg-dark text-light border-secondary">
      <i class="bi ${icon} me-2"></i>
      <strong class="me-auto text-light"></strong>
      <small class="text-muted">Just now</small>
      <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
    <div class="toast-body bg-dark text-light"></div>
  `;
  toastEl.querySelector('strong').textContent = title;
  toastEl.querySelector('.toast-body').textContent = message;
  toastContainer.appendChild(toastEl);
  const toast = new bootstrap.Toast(toastEl);
  toast.show();

  toastEl.addEventListener('hidden.bs.toast', () => {
    toastEl.remove();
  });
}

function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
  if (!navigator.clipboard) {
    showToast('Clipboard', 'Clipboard access is not available in this browser.', 'danger');
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    showToast('Clipboard', successMsg, 'info');
  }).catch(err => {
    console.error('Failed to copy: ', err);
  });
}
