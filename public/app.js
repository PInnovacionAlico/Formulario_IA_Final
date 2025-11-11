function savedWebhook() {
  return localStorage.getItem('webhookUrl') || '';
}

document.getElementById('webhookUrl').value = savedWebhook();
document.getElementById('saveWebhook').addEventListener('click', () => {
  const v = document.getElementById('webhookUrl').value.trim();
  localStorage.setItem('webhookUrl', v);
  alert('Webhook guardado para pruebas: ' + v);
});

function headersWithWebhook() {
  const url = savedWebhook();
  return url ? { 'x-webhook-url': url } : {};
}

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = { name: fd.get('name'), email: fd.get('email'), password: fd.get('password') };
  const resEl = document.getElementById('registerResult');
  resEl.textContent = 'Enviando...';
  try {
    const res = await fetch('/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headersWithWebhook() }, body: JSON.stringify(body) });
    const data = await res.json();
    resEl.textContent = JSON.stringify(data);
  } catch (err) {
    resEl.textContent = String(err);
  }
});

document.getElementById('changeForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = { email: fd.get('email'), oldPassword: fd.get('oldPassword'), newPassword: fd.get('newPassword') };
  const resEl = document.getElementById('changeResult');
  resEl.textContent = 'Enviando...';
  try {
    const res = await fetch('/api/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headersWithWebhook() }, body: JSON.stringify(body) });
    const data = await res.json();
    resEl.textContent = JSON.stringify(data);
  } catch (err) {
    resEl.textContent = String(err);
  }
});

document.getElementById('uploadForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  const resEl = document.getElementById('uploadResult');
  resEl.textContent = 'Subiendo...';
  try {
    const res = await fetch('/api/upload', { method: 'POST', headers: { ...headersWithWebhook() }, body: fd });
    const data = await res.json();
    resEl.textContent = JSON.stringify(data);
  } catch (err) {
    resEl.textContent = String(err);
  }
});
