'use strict';

document.addEventListener('DOMContentLoaded', () => {

  const toggle = document.getElementById('navToggle');
  const links  = document.getElementById('navLinks');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      const open = links.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('click', e => {
      if (!toggle.contains(e.target) && !links.contains(e.target)) {
        links.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  document.querySelectorAll('.alert-close').forEach(btn => {
    btn.addEventListener('click', () => dismissAlert(btn.closest('.alert')));
  });
  document.querySelectorAll('[data-auto-dismiss]').forEach(el => {
    setTimeout(() => dismissAlert(el), 5000);
  });
  function dismissAlert(el) {
    if (!el) return;
    el.style.transition = 'opacity .3s ease, transform .3s ease';
    el.style.opacity    = '0';
    el.style.transform  = 'translateX(20px)';
    setTimeout(() => el.remove(), 300);
  }

  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input    = document.getElementById(targetId);
      if (!input) return;
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? '\uD83D\uDE4A' : '\uD83D\uDC41';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  const pwInput  = document.getElementById('password');
  const fillEl   = document.getElementById('strengthFill');
  const labelEl  = document.getElementById('strengthLabel');

  if (pwInput && fillEl && labelEl) {
    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      const score = scorePassword(pw);
      const levels = [
        { pct: '0%',   bg: 'transparent', label: '' },
        { pct: '25%',  bg: '#ef4444',     label: 'Weak' },
        { pct: '50%',  bg: '#f59e0b',     label: 'Fair' },
        { pct: '75%',  bg: '#3b82f6',     label: 'Good' },
        { pct: '100%', bg: '#10b981',     label: 'Strong' },
      ];
      const lvl = levels[score];
      fillEl.style.width      = lvl.pct;
      fillEl.style.background = lvl.bg;
      labelEl.textContent     = lvl.label;
      labelEl.style.color     = lvl.bg;
    });
  }

  function scorePassword(pw) {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8)  s++;
    if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
    if (/\d/.test(pw))   s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(4, s);
  }

  const confirmInput = document.getElementById('confirm_password');
  const matchFeedback = document.getElementById('matchFeedback');

  if (pwInput && confirmInput && matchFeedback) {
    const checkMatch = () => {
      if (!confirmInput.value) { matchFeedback.textContent = ''; return; }
      if (confirmInput.value === pwInput.value) {
        matchFeedback.textContent = '✓ Passwords match';
        matchFeedback.style.color = '#10b981';
      } else {
        matchFeedback.textContent = '✕ Passwords do not match';
        matchFeedback.style.color = '#ef4444';
      }
    };
    confirmInput.addEventListener('input', checkMatch);
    pwInput.addEventListener('input', checkMatch);
  }

  document.querySelectorAll('.auth-form').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('[type="submit"]');
      if (btn) {
        btn.textContent = 'Please wait…';
        btn.disabled = true;
        setTimeout(() => { btn.disabled = false; btn.textContent = btn.dataset.label || btn.textContent; }, 6000);
      }
    });
  });

});
