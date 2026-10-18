/* SecureCloud front-end helpers.
 * No inline handlers, no external libraries: everything here is progressive
 * enhancement. Uploads work even when JavaScript is disabled.
 */
(function () {
  'use strict';

  function formatBytes(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    var value = Number(bytes);
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
    return (i === 0 ? value.toFixed(0) : value.toFixed(2)) + ' ' + units[i];
  }

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function show(id, visible) {
    var el = document.getElementById(id);
    if (el) el.hidden = !visible;
  }

  /* ------------------------------------------------------------ uploads */
  function initUpload(options) {
    var form = document.getElementById(options.formId || 'upload-form');
    var input = document.getElementById(options.inputId || 'file-input');
    var dropzone = document.getElementById('dropzone');
    var button = document.getElementById('upload-button');
    if (!form || !input) return;

    var blockSize = Number(options.blockSize) || 1048576;
    var maxBytes = Number(options.maxBytes) || 0;

    function describe(file) {
      if (!file) { show('selection', false); return; }
      setText('sel-name', file.name);
      setText('sel-size', formatBytes(file.size) + ' (' + file.size + ' bytes)');
      var blocks = file.size === 0 ? 0 : Math.ceil(file.size / blockSize);
      setText('sel-blocks', blocks + ' block' + (blocks === 1 ? '' : 's') +
        ' of ' + formatBytes(blockSize));
      show('selection', true);
      var hint = document.getElementById('dropzone-help');
      if (maxBytes && file.size > maxBytes && hint) {
        hint.textContent = 'This file is larger than the allowed ' + formatBytes(maxBytes) + '.';
        hint.style.color = '#b02a37';
      } else if (hint) {
        hint.textContent = 'Documents, images, PDFs, ZIP archives and more — up to ' +
          formatBytes(maxBytes) + ' per file.';
        hint.style.color = '';
      }
    }

    input.addEventListener('change', function () {
      describe(input.files && input.files[0]);
    });

    if (dropzone) {
      ['dragenter', 'dragover'].forEach(function (type) {
        dropzone.addEventListener(type, function (event) {
          event.preventDefault();
          dropzone.classList.add('is-active');
        });
      });
      ['dragleave', 'drop'].forEach(function (type) {
        dropzone.addEventListener(type, function (event) {
          event.preventDefault();
          dropzone.classList.remove('is-active');
        });
      });
      dropzone.addEventListener('drop', function (event) {
        var files = event.dataTransfer && event.dataTransfer.files;
        if (files && files.length) {
          input.files = files;
          describe(files[0]);
        }
      });
      dropzone.addEventListener('click', function (event) {
        if (event.target !== input) input.click();
      });
      dropzone.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          input.click();
        }
      });
    }

    form.addEventListener('submit', function (event) {
      var file = input.files && input.files[0];
      if (!file) return;                       // native validation shows the message
      if (maxBytes && file.size > maxBytes) return;  // server enforces it as well
      if (!window.FormData || !window.XMLHttpRequest) return;  // plain POST fallback

      event.preventDefault();
      var bar = document.getElementById('progress-bar');
      var wrap = document.getElementById('progress-wrap');
      var text = document.getElementById('progress-text');
      show('progress-wrap', true);
      if (bar) bar.style.width = '0%';
      if (text) text.textContent = 'Uploading ' + file.name + ' (' + formatBytes(file.size) + ')…';
      if (button) { button.disabled = true; button.textContent = 'Uploading…'; }

      var xhr = new XMLHttpRequest();
      xhr.open('POST', form.action || window.location.href, true);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.upload.addEventListener('progress', function (event) {
        if (!event.lengthComputable) return;
        var percent = Math.round((event.loaded / event.total) * 100);
        if (bar) bar.style.width = percent + '%';
        if (text) {
          text.textContent = percent < 100
            ? 'Uploading… ' + percent + '% (' + formatBytes(event.loaded) + ' of ' + formatBytes(event.total) + ')'
            : 'Encrypting and storing blocks…';
        }
      });
      xhr.onreadystatechange = function () {
        if (xhr.readyState !== 4) return;
        if (xhr.status >= 200 && xhr.status < 400) {
          if (bar) bar.style.width = '100%';
          if (text) text.textContent = 'Upload complete. Redirecting…';
          try {
            var payload = JSON.parse(xhr.responseText);
            if (payload && payload.file) {
              window.location.href = '/files/' + payload.file.id;
              return;
            }
          } catch (err) { /* fall through to a full reload */ }
          window.location.reload();
        } else {
          if (text) text.textContent = 'Upload failed (HTTP ' + xhr.status + '). The file was not stored.';
          if (button) { button.disabled = false; button.textContent = 'Try again'; }
          show('progress-wrap', true);
        }
      };
      xhr.send(new FormData(form));
    });

    /* Register password strength feedback when present on this page. */
    initPasswordStrength();
  }

  /* ------------------------------------------------------ password meter */
  function initPasswordStrength() {
    var input = document.querySelector('[data-strength-for="password"]');
    var field = document.getElementById('password');
    if (!input || !field) return;
    var text = document.querySelector('[data-strength-text]');
    field.addEventListener('input', function () {
      var value = field.value || '';
      var score = 0;
      if (value.length >= 10) score += 1;
      if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
      if (/[0-9]/.test(value)) score += 1;
      if (/[^A-Za-z0-9]/.test(value) && value.length >= 12) score += 1;
      input.setAttribute('data-score', String(score));
      if (text) {
        var labels = ['Too short', 'Weak', 'Fair', 'Good', 'Strong'];
        text.textContent = value ? labels[score] : 'Use a mix of letters, numbers and symbols.';
      }
    });
  }

  /* --------------------------------------------------------- confirmations */
  function initConfirmations() {
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
      form.addEventListener('submit', function (event) {
        if (form.getAttribute('data-confirmed') === '1') return;
        var message = form.getAttribute('data-confirm') || 'Are you sure?';
        if (!window.confirm(message)) {
          event.preventDefault();
          return;
        }
        form.setAttribute('data-confirmed', '1');
      });
    });
  }

  /* ------------------------------------------------------- storage check */
  function initStorageCheck(buttonId, targetId) {
    var button = document.getElementById(buttonId);
    var target = document.getElementById(targetId);
    if (!button || !target) return;
    button.addEventListener('click', function () {
      button.disabled = true;
      button.textContent = 'Testing…';
      fetch('/settings/storage-check', {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      }).then(function (response) {
        return response.json();
      }).then(function (data) {
        var badge = data.ok ? 'badge-ok' : 'badge-danger';
        var label = data.ok ? 'OK' : 'Failed';
        var detail = data.details && data.details.missing_settings
          ? ' Missing: ' + data.details.missing_settings.join(', ')
          : '';
        target.innerHTML = '<table class="kv-table"><tbody>' +
          '<tr><th>Backend</th><td>' + escapeHtml(data.backend || '') + '</td></tr>' +
          '<tr><th>Result</th><td><span class="badge ' + badge + '">' + label + '</span> ' +
          escapeHtml(data.message || '') + escapeHtml(detail) + '</td></tr>' +
          '</tbody></table>';
      }).catch(function () {
        target.innerHTML = '<p class="alert alert-danger small">The connectivity test could not be completed.</p>';
      }).finally(function () {
        button.disabled = false;
        button.textContent = 'Re-run connectivity test';
      });
    });
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char];
    });
  }

  window.SecureCloud = {
    initUpload: initUpload,
    initConfirmations: initConfirmations,
    initStorageCheck: initStorageCheck,
    formatBytes: formatBytes
  };

  document.addEventListener('DOMContentLoaded', function () {
    initConfirmations();
    initPasswordStrength();
  });
})();
