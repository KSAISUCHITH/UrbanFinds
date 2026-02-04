function showAlert(message, type = 'info') {
  const alertDiv = document.createElement('div');
  alertDiv.className = `alert alert-${type} fade-in`;
  alertDiv.textContent = message;

  const container = document.querySelector('.container');
  if (container) {
    container.insertBefore(alertDiv, container.firstChild);

    setTimeout(() => {
      alertDiv.style.opacity = '0';
      setTimeout(() => alertDiv.remove(), 300);
    }, 5000);
  }
}

function formatCurrency(amount) {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 0
  }).format(amount);
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return new Intl.DateTimeFormat('en-IN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
    document.body.style.overflow = '';
  }
}

document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    closeModal(e.target.id);
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const activeModal = document.querySelector('.modal-overlay.active');
    if (activeModal) {
      closeModal(activeModal.id);
    }
  }
});

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return false;

  let isValid = true;
  const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');

  inputs.forEach(input => {
    const errorElement = input.parentElement.querySelector('.form-error');

    if (!input.value.trim()) {
      isValid = false;
      input.style.borderColor = 'var(--accent-red)';
      if (errorElement) {
        errorElement.textContent = 'This field is required';
      }
    } else if (input.type === 'email' && !validateEmail(input.value)) {
      isValid = false;
      input.style.borderColor = 'var(--accent-red)';
      if (errorElement) {
        errorElement.textContent = 'Please enter a valid email';
      }
    } else {
      input.style.borderColor = '';
      if (errorElement) {
        errorElement.textContent = '';
      }
    }
  });

  return isValid;
}

document.addEventListener('input', (e) => {
  if (e.target.matches('input, select, textarea')) {
    e.target.style.borderColor = '';
    const errorElement = e.target.parentElement.querySelector('.form-error');
    if (errorElement) {
      errorElement.textContent = '';
    }
  }
});

function filterProperties() {
  const searchTerm = document.getElementById('search')?.value.toLowerCase() || '';
  const typeFilter = document.getElementById('typeFilter')?.value || 'all';
  const minPrice = parseFloat(document.getElementById('minPrice')?.value) || 0;
  const maxPrice = parseFloat(document.getElementById('maxPrice')?.value) || Infinity;

  const propertyCards = document.querySelectorAll('.property-card');
  let visibleCount = 0;

  propertyCards.forEach(card => {
    const title = card.querySelector('.property-title')?.textContent.toLowerCase() || '';
    const address = card.querySelector('.property-address')?.textContent.toLowerCase() || '';
    const type = card.dataset.type?.toLowerCase() || '';
    const price = parseFloat(card.dataset.price) || 0;

    const matchesSearch = title.includes(searchTerm) || address.includes(searchTerm);
    const matchesType = typeFilter === 'all' || type === typeFilter;
    const matchesPrice = price >= minPrice && price <= maxPrice;

    if (matchesSearch && matchesType && matchesPrice) {
      card.style.display = '';
      visibleCount++;
    } else {
      card.style.display = 'none';
    }
  });

  const emptyState = document.getElementById('emptyState');
  if (emptyState) {
    emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
  }

  const resultsCount = document.getElementById('resultsCount');
  if (resultsCount) {
    resultsCount.textContent = `${visibleCount} properties found`;
  }
}

function previewImage(input) {
  const preview = document.getElementById('imagePreview');
  if (!preview) return;

  if (input.files && input.files[0]) {
    const reader = new FileReader();

    reader.onload = function (e) {
      preview.innerHTML = `<img src="${e.target.result}" alt="Preview" style="max-width: 100%; border-radius: var(--radius-md);">`;
    };

    reader.readAsDataURL(input.files[0]);
  }
}

function confirmAction(message, callback) {
  if (confirm(message)) {
    callback();
  }
}

async function updateApplicationStatus(applicationId, status) {
  try {
    const response = await fetch(`/api/applications/${applicationId}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status })
    });

    if (response.ok) {
      showAlert(`Application ${status} successfully`, 'success');
      setTimeout(() => location.reload(), 1500);
    } else {
      const error = await response.json();
      showAlert(error.message || 'Failed to update application', 'error');
    }
  } catch (error) {
    showAlert('An error occurred. Please try again.', 'error');
  }
}

async function deleteProperty(propertyId) {
  confirmAction('Are you sure you want to delete this property?', async () => {
    try {
      const response = await fetch(`/api/properties/${propertyId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        showAlert('Property deleted successfully', 'success');
        setTimeout(() => location.reload(), 1500);
      } else {
        const error = await response.json();
        showAlert(error.message || 'Failed to delete property', 'error');
      }
    } catch (error) {
      showAlert('An error occurred. Please try again.', 'error');
    }
  });
}

async function toggleUserStatus(userId, currentStatus) {
  const newStatus = currentStatus === 'active' ? 'disabled' : 'active';
  const action = newStatus === 'active' ? 'enable' : 'disable';

  confirmAction(`Are you sure you want to ${action} this user?`, async () => {
    try {
      const response = await fetch(`/api/users/${userId}/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });

      if (response.ok) {
        showAlert(`User ${action}d successfully`, 'success');
        setTimeout(() => location.reload(), 1500);
      } else {
        const error = await response.json();
        showAlert(error.message || `Failed to ${action} user`, 'error');
      }
    } catch (error) {
      showAlert('An error occurred. Please try again.', 'error');
    }
  });
}

async function removeProperty(propertyId) {
  confirmAction('Are you sure you want to remove this property from the platform?', async () => {
    try {
      const response = await fetch(`/api/admin/properties/${propertyId}/remove`, {
        method: 'POST'
      });

      if (response.ok) {
        showAlert('Property removed successfully', 'success');
        setTimeout(() => location.reload(), 1500);
      } else {
        const error = await response.json();
        showAlert(error.message || 'Failed to remove property', 'error');
      }
    } catch (error) {
      showAlert('An error occurred. Please try again.', 'error');
    }
  });
}

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    const href = this.getAttribute('href');
    if (href !== '#') {
      e.preventDefault();
      const target = document.querySelector(href);
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    }
  });
});

function setActiveNavLink() {
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-link');

  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPath || (currentPath.includes(href) && href !== '/')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setActiveNavLink();

  const cards = document.querySelectorAll('.card, .property-card, .stat-card');
  cards.forEach((card, index) => {
    setTimeout(() => {
      card.classList.add('fade-in');
    }, index * 50);
  });
});

let searchTimeout;
document.addEventListener('input', (e) => {
  if (e.target.id === 'search' || e.target.id === 'typeFilter' ||
    e.target.id === 'minPrice' || e.target.id === 'maxPrice') {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(filterProperties, 300);
  }
});

document.addEventListener('submit', (e) => {
  const form = e.target;
  const submitButton = form.querySelector('button[type="submit"]');

  if (submitButton && !form.hasAttribute('data-no-loading')) {
    const originalText = submitButton.textContent;
    submitButton.disabled = true;
    submitButton.textContent = 'Processing...';

    setTimeout(() => {
      submitButton.disabled = false;
      submitButton.textContent = originalText;
    }, 10000);
  }
});

function updatePriceDisplay() {
  const minPrice = document.getElementById('minPrice');
  const maxPrice = document.getElementById('maxPrice');
  const minDisplay = document.getElementById('minPriceDisplay');
  const maxDisplay = document.getElementById('maxPriceDisplay');

  if (minPrice && minDisplay) {
    minDisplay.textContent = formatCurrency(minPrice.value || 0);
  }

  if (maxPrice && maxDisplay) {
    maxDisplay.textContent = formatCurrency(maxPrice.value || 10000000);
  }
}

function updateNotificationBadge(count) {
  const badge = document.getElementById('notificationBadge');
  if (badge) {
    if (count > 0) {
      badge.textContent = count > 99 ? '99+' : count;
      badge.style.display = 'inline-flex';
    } else {
      badge.style.display = 'none';
    }
  }
}

function checkNewNotifications() {
  fetch('/api/notifications/unread-count')
    .then(response => response.json())
    .then(data => {
      if (data.count !== undefined) {
        updateNotificationBadge(data.count);
      }
    })
    .catch(error => console.error('Failed to fetch notifications:', error));
}

if (document.querySelector('.navbar-nav')) {
  setInterval(checkNewNotifications, 30000);
  checkNewNotifications();
}

window.UrbanFinds = {
  showAlert,
  formatCurrency,
  formatDate,
  openModal,
  closeModal,
  validateForm,
  filterProperties,
  previewImage,
  confirmAction,
  updateApplicationStatus,
  deleteProperty,
  toggleUserStatus,
  removeProperty,
  updatePriceDisplay,
  updateNotificationBadge
};
