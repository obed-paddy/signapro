// SignaPro — signature de documents PDF, 100 % locale (aucun fichier n'est envoyé sur internet).
import * as pdfjsLib from './pdf.min.mjs';

pdfjsLib.GlobalWorkerOptions.workerSrc = new URL('./pdf.worker.min.mjs', import.meta.url).href;
const { PDFDocument, degrees } = window.PDFLib;

const $ = (id) => document.getElementById(id);
const clamp = (v, a, b) => Math.min(Math.max(v, a), b);

/* ------------------------------------------------------------------ état */
const S = {
  name: 'document',
  bytes: null,          // octets du PDF d'origine (jamais modifiés)
  pdf: null,            // document pdf.js
  pages: [],            // { page, wPt, hPt, view, rotate, el, canvas, layer, visible, key, task }
  items: [],            // éléments posés : { id, page, kind, src, ratio, fx, fy, fw }
  armed: null,          // élément en attente d'être posé
  selected: null,
  zoom: 1,
  baseW: 320,
  dirty: false,
  exportBlob: null,
  exportName: '',
};
let nextId = 1;

/* ------------------------------------------------------------ utilitaires */
let toastTimer;
function toast(msg, ms = 3200) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
function busy(on, text = 'Patientez…') {
  $('busyText').textContent = text;
  $('busy').hidden = !on;
}
function openDlg(d) { if (!d.open) d.showModal(); }
function closeDlg(d) { if (d.open) d.close(); }

function todayFr() { return new Date().toLocaleDateString('fr-FR'); }

function loadImage(src) {
  return new Promise((res, rej) => {
    const i = new Image();
    i.onload = () => res(i);
    i.onerror = () => rej(new Error('image illisible'));
    i.src = src;
  });
}
function fileToDataURL(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.onerror = () => rej(r.error);
    r.readAsDataURL(file);
  });
}

// Recadre un canvas autour des pixels non transparents.
function trimCanvas(src, pad = 6) {
  const w = src.width, h = src.height;
  const data = src.getContext('2d').getImageData(0, 0, w, h).data;
  let minX = w, minY = h, maxX = -1, maxY = -1;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (data[(y * w + x) * 4 + 3] > 10) {
        if (x < minX) minX = x;
        if (x > maxX) maxX = x;
        if (y < minY) minY = y;
        if (y > maxY) maxY = y;
      }
    }
  }
  if (maxX < 0) return null;
  minX = Math.max(0, minX - pad); minY = Math.max(0, minY - pad);
  maxX = Math.min(w - 1, maxX + pad); maxY = Math.min(h - 1, maxY + pad);
  const cw = maxX - minX + 1, ch = maxY - minY + 1;
  const out = document.createElement('canvas');
  out.width = cw; out.height = ch;
  out.getContext('2d').drawImage(src, minX, minY, cw, ch, 0, 0, cw, ch);
  return out;
}
function limitWidth(canvas, maxW) {
  if (canvas.width <= maxW) return canvas;
  const k = maxW / canvas.width;
  const out = document.createElement('canvas');
  out.width = maxW; out.height = Math.max(1, Math.round(canvas.height * k));
  const ctx = out.getContext('2d');
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(canvas, 0, 0, out.width, out.height);
  return out;
}
function canvasToAsset(canvas) {
  return { src: canvas.toDataURL('image/png'), ratio: canvas.width / canvas.height };
}

/* ----------------------------------------------------- stockage local */
const STORE_KEY = 'signapro.assets.v1';      // signature/cachet en clair (sans code PIN)
const SEC_KEY = 'signapro.sec.v1';           // paramètres du code PIN (sel + preuve de validité)
const ENC_KEY = 'signapro.assets.enc.v1';    // signature/cachet chiffrés (avec code PIN)
const FAIL_KEY = 'signapro.fails.v1';        // essais de code PIN ratés

const assets = {};
function setAssets(o) {
  for (const k of Object.keys(assets)) delete assets[k];
  Object.assign(assets, o || {});
}
let sec = null;
try { sec = JSON.parse(localStorage.getItem(SEC_KEY) || 'null'); } catch { sec = null; }
if (!sec) { try { setAssets(JSON.parse(localStorage.getItem(STORE_KEY) || '{}')); } catch { /* vide */ } }

let cryptoKey = null;   // clé de chiffrement, gardée en mémoire seulement tant que l'application est déverrouillée
let saveChain = Promise.resolve();
function saveAssets() {
  saveChain = saveChain.then(async () => {
    try {
      if (sec) {
        if (!cryptoKey) return; // verrouillé : on n'écrit rien
        localStorage.setItem(ENC_KEY, JSON.stringify(await encJSON(cryptoKey, assets)));
        localStorage.removeItem(STORE_KEY);
      } else {
        localStorage.setItem(STORE_KEY, JSON.stringify(assets));
      }
    } catch {
      toast("Impossible d'enregistrer sur cet appareil (stockage plein ou bloqué).");
    }
  });
  return saveChain;
}

/* ---------------------------------------------- sécurité : code PIN */
const hasCrypto = !!(window.crypto && window.crypto.subtle);
const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(pin, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
  return { iv: b64(iv), ct: b64(ct) };
}
async function decJSON(key, blob) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function checkPin(pin) {           // renvoie la clé si le code est bon, sinon lève une erreur
  const key = await deriveKey(pin, unb64(sec.salt), sec.iter);
  await decJSON(key, sec.check);
  return key;
}
const PIN_RE = /^\d{4,8}$/;

function readFails() { try { return JSON.parse(localStorage.getItem(FAIL_KEY) || '{"n":0,"until":0}'); } catch { return { n: 0, until: 0 }; } }
function writeFails(f) { try { localStorage.setItem(FAIL_KEY, JSON.stringify(f)); } catch { /* ignore */ } }

function lock() {
  if (!sec) return;
  cryptoKey = null;
  setAssets({});
  cancelArm();
  document.querySelectorAll('dialog[open]').forEach((d) => d.close());
  $('lock').hidden = false;
  $('lockPin').value = '';
  $('lockMsg').textContent = 'Entrez votre code PIN';
  clearTimeout(idleTimer);
  refreshAssets();
  setTimeout(() => $('lockPin').focus(), 50);
}

async function tryUnlock() {
  const f = readFails();
  const now = Date.now();
  if (now < f.until) { $('lockMsg').textContent = `Trop d'essais. Réessayez dans ${Math.ceil((f.until - now) / 1000)} s.`; return; }
  const pin = $('lockPin').value;
  if (!PIN_RE.test(pin)) { $('lockMsg').textContent = 'Le code compte 4 à 8 chiffres.'; return; }
  $('lockOk').disabled = true;
  try {
    const key = await checkPin(pin);
    const enc = localStorage.getItem(ENC_KEY);
    const data = enc ? await decJSON(key, JSON.parse(enc)) : {};
    cryptoKey = key;
    setAssets(data);
    writeFails({ n: 0, until: 0 });
    $('lock').hidden = true;
    $('lockPin').value = '';
    refreshAssets();
    resetIdle();
  } catch {
    f.n += 1;
    $('lockPin').value = '';
    if (f.n >= 5) {
      const wait = Math.min(600, 15 * 2 ** (f.n - 5));
      f.until = Date.now() + wait * 1000;
      $('lockMsg').textContent = `Trop d'essais. Réessayez dans ${wait} s.`;
    } else {
      $('lockMsg').textContent = `Code incorrect (${5 - f.n} essai(s) avant blocage).`;
    }
    writeFails(f);
  } finally {
    $('lockOk').disabled = false;
  }
}
$('lockOk').addEventListener('click', tryUnlock);
$('lockPin').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
$('lockReset').addEventListener('click', () => {
  if (!confirm("Code oublié : vous pouvez le retirer, mais votre signature, votre paraphe et votre cachet enregistrés seront effacés (il faudra les refaire). Continuer ?")) return;
  [SEC_KEY, ENC_KEY, STORE_KEY, FAIL_KEY].forEach((k) => localStorage.removeItem(k));
  sec = null; cryptoKey = null; setAssets({});
  $('lock').hidden = true;
  refreshAssets();
  toast('Code retiré. Refaites votre signature dans Réglages.', 4500);
});

// verrouillage automatique : inactivité de 3 minutes, ou application en arrière-plan plus d'une minute
let idleTimer = null;
const IDLE_MS = 3 * 60 * 1000;
function resetIdle() {
  clearTimeout(idleTimer);
  if (sec && cryptoKey) idleTimer = setTimeout(lock, IDLE_MS);
}
['pointerdown', 'keydown', 'scroll'].forEach((t) => document.addEventListener(t, resetIdle, { passive: true, capture: true }));
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (sec && cryptoKey && hiddenAt && Date.now() - hiddenAt > 60000) lock();
});

// fenêtre de création / changement / retrait du code PIN
let pinMode = 'set';
function openPinDialog(mode) {
  pinMode = mode;
  $('pinTitle').textContent = { set: 'Définir un code PIN', change: 'Changer le code PIN', off: 'Retirer le code PIN' }[mode];
  $('pinCurRow').hidden = mode === 'set';
  $('pinNewRows').hidden = mode === 'off';
  ['pinCur', 'pinNew', 'pinNew2'].forEach((id) => { $(id).value = ''; });
  $('pinErr').hidden = true;
  closeDlg($('assetsDialog'));
  openDlg($('pinDialog'));
}
function pinError(msg) { $('pinErr').textContent = msg; $('pinErr').hidden = false; }
$('pinCancel').addEventListener('click', () => closeDlg($('pinDialog')));
$('pinSave').addEventListener('click', async () => {
  try {
    if (pinMode !== 'set') {
      try { await checkPin($('pinCur').value); } catch { pinError('Code actuel incorrect.'); return; }
    }
    if (pinMode === 'off') {
      sec = null; cryptoKey = null;
      localStorage.removeItem(SEC_KEY); localStorage.removeItem(ENC_KEY); localStorage.removeItem(FAIL_KEY);
      await saveAssets();
      closeDlg($('pinDialog'));
      toast('Code PIN retiré.');
      return;
    }
    const a = $('pinNew').value, b = $('pinNew2').value;
    if (!PIN_RE.test(a)) { pinError('Le code doit compter 4 à 8 chiffres.'); return; }
    if (a !== b) { pinError('Les deux codes ne sont pas identiques.'); return; }
    $('pinSave').disabled = true;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iter = 150000;
    const key = await deriveKey(a, salt, iter);
    const check = await encJSON(key, { ok: 1 });
    sec = { salt: b64(salt), iter, check };
    cryptoKey = key;
    localStorage.setItem(SEC_KEY, JSON.stringify(sec));
    await saveAssets(); // chiffre et supprime la version en clair
    writeFails({ n: 0, until: 0 });
    closeDlg($('pinDialog'));
    resetIdle();
    toast(pinMode === 'change' ? 'Code PIN modifié.' : 'Code PIN activé : votre signature est chiffrée.', 4000);
  } catch (e) {
    console.error(e);
    pinError("Impossible d'enregistrer le code PIN sur cet appareil.");
  } finally {
    $('pinSave').disabled = false;
  }
});
$('secSet').addEventListener('click', () => openPinDialog('set'));
$('secChange').addEventListener('click', () => openPinDialog('change'));
$('secOff').addEventListener('click', () => openPinDialog('off'));
$('secLock').addEventListener('click', lock);

function refreshSecurityUI() {
  const st = $('secState');
  if (!hasCrypto) {
    st.textContent = "Le code PIN n'est pas disponible dans ce mode d'ouverture (il faut l'adresse https de l'application).";
    ['secSet', 'secChange', 'secOff', 'secLock'].forEach((id) => { $(id).hidden = true; });
    return;
  }
  if (sec) {
    st.textContent = 'Code PIN activé : l\'application se verrouille toute seule, et votre signature est chiffrée sur cet appareil.';
  } else {
    st.textContent = "Pas de code PIN : toute personne qui a accès à cet appareil peut utiliser votre signature.";
  }
  $('secSet').hidden = !!sec;
  $('secChange').hidden = !sec;
  $('secOff').hidden = !sec;
  $('secLock').hidden = !sec;
}

let pinAdvised = false;
function advisePin() {
  if (hasCrypto && !sec && !pinAdvised) {
    pinAdvised = true;
    setTimeout(() => toast('Conseil : activez un code PIN dans Réglages pour protéger votre signature.', 5500), 600);
  }
}

/* ------------------------------------------------- ouverture de fichiers */
async function imageToPdfBytes(file) {
  const dataUrl = await fileToDataURL(file);
  const img = await loadImage(dataUrl);
  const maxSide = 2600;
  const k = Math.min(1, maxSide / Math.max(img.naturalWidth, img.naturalHeight));
  const c = document.createElement('canvas');
  c.width = Math.round(img.naturalWidth * k);
  c.height = Math.round(img.naturalHeight * k);
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, c.width, c.height);
  ctx.drawImage(img, 0, 0, c.width, c.height);
  const jpg = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.9));
  const doc = await PDFDocument.create();
  const emb = await doc.embedJpg(new Uint8Array(await jpg.arrayBuffer()));
  const pw = 595.28; // largeur A4 en points
  const ph = pw * (c.height / c.width);
  const page = doc.addPage([pw, ph]);
  page.drawImage(emb, { x: 0, y: 0, width: pw, height: ph });
  return await doc.save();
}

async function handleFile(file) {
  if (!file) return;
  const name = file.name || 'document';
  const ext = (name.split('.').pop() || '').toLowerCase();
  const wordLike = ['doc', 'docx', 'odt', 'rtf', 'xls', 'xlsx', 'ppt', 'pptx'];
  try {
    if (wordLike.includes(ext)) { openDlg($('wordDialog')); return; }
    busy(true, 'Ouverture du document…');
    let bytes;
    const isImg = (file.type || '').startsWith('image/') || ['jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp'].includes(ext);
    if (isImg) {
      bytes = await imageToPdfBytes(file);
    } else {
      bytes = new Uint8Array(await file.arrayBuffer());
      const head = new TextDecoder().decode(bytes.subarray(0, 1024));
      if (!head.includes('%PDF')) { busy(false); toast('Format non pris en charge. Choisissez un PDF ou une photo.'); return; }
    }
    await openPdf(bytes, name.replace(/\.[^.]+$/, '') || 'document');
  } catch (e) {
    console.error(e);
    toast("Impossible d'ouvrir ce fichier.");
  } finally {
    busy(false);
  }
}

async function openPdf(bytes, baseName) {
  if (S.items.length && S.dirty && !confirm('Les éléments posés sur le document actuel seront perdus. Continuer ?')) return;
  let pdf;
  try {
    pdf = await pdfjsLib.getDocument({ data: bytes.slice() }).promise;
  } catch (e) {
    if (e && e.name === 'PasswordException') toast('Ce PDF est protégé par un mot de passe : retirez la protection d\'abord.', 5000);
    else toast("Ce PDF est illisible ou endommagé.");
    return;
  }
  resetDoc();
  S.pdf = pdf;
  S.bytes = bytes;
  S.name = baseName;
  document.body.classList.add('has-doc');
  computeBaseWidth();
  const host = $('pages');
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const vp = page.getViewport({ scale: 1 });
    const rotate = ((page.rotate % 360) + 360) % 360;
    const el = document.createElement('div');
    el.className = 'page';
    el.dataset.i = String(i - 1);
    el.style.aspectRatio = `${vp.width} / ${vp.height}`;
    const canvas = document.createElement('canvas');
    const layer = document.createElement('div');
    layer.className = 'layer';
    el.append(canvas, layer);
    host.append(el);
    const pg = { page, wPt: vp.width, hPt: vp.height, view: page.view, rotate, el, canvas, layer, visible: false, key: null, task: null };
    S.pages.push(pg);
    el.addEventListener('click', (ev) => onPageClick(ev, pg));
    io.observe(el);
  }
  applyWidth();
  $('btnExport').disabled = false;
  $('viewer').scrollTop = 0;
  updatePageInfo();
}

function resetDoc() {
  cancelArm();
  S.pages.forEach((p) => { io.unobserve(p.el); if (p.task) { try { p.task.cancel(); } catch {} } });
  $('pages').replaceChildren();
  if (S.pdf) { try { S.pdf.destroy(); } catch {} }
  S.pdf = null; S.bytes = null; S.pages = []; S.items = []; S.selected = null; S.dirty = false;
  $('btnExport').disabled = true;
  $('pageInfo').textContent = '';
}

/* ----------------------------------------------------- affichage / zoom */
function computeBaseWidth() {
  const vw = $('viewer').clientWidth || window.innerWidth;
  S.baseW = clamp(vw - 24, 260, 900);
}
function applyWidth() {
  const w = Math.round(S.baseW * S.zoom);
  $('pages').style.setProperty('--pw', w + 'px');
  S.pages.forEach((p) => { if (p.visible) renderPage(p); else p.key = null; });
}
function setZoom(z) {
  S.zoom = clamp(z, 0.6, 3);
  applyWidth();
}
const io = new IntersectionObserver((entries) => {
  for (const e of entries) {
    const pg = S.pages[+e.target.dataset.i];
    if (!pg) continue;
    pg.visible = e.isIntersecting;
    if (e.isIntersecting) renderPage(pg);
    else releasePage(pg);
  }
}, { root: $('viewer'), rootMargin: '700px 0px' });

async function renderPage(pg) {
  const cssW = Math.round(S.baseW * S.zoom);
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const key = `${cssW}|${dpr}`;
  if (pg.key === key) return;
  pg.key = key;
  if (pg.task) { try { pg.task.cancel(); } catch {} pg.task = null; }
  let scale = (cssW * dpr) / pg.wPt;
  const maxPixels = 14e6;
  const px = pg.wPt * scale * pg.hPt * scale;
  if (px > maxPixels) scale *= Math.sqrt(maxPixels / px);
  const vp = pg.page.getViewport({ scale });
  const off = document.createElement('canvas'); // rendu hors écran puis copie : pas de page blanche qui clignote
  off.width = Math.floor(vp.width);
  off.height = Math.floor(vp.height);
  try {
    const task = pg.page.render({ canvasContext: off.getContext('2d'), viewport: vp });
    pg.task = task;
    await task.promise;
    if (pg.key !== key) return;
    pg.canvas.width = off.width;
    pg.canvas.height = off.height;
    pg.canvas.getContext('2d').drawImage(off, 0, 0);
  } catch (e) {
    if (!(e && e.name === 'RenderingCancelledException')) { console.error(e); pg.key = null; }
  } finally {
    if (pg.task && pg.key === key) pg.task = null;
  }
}
function releasePage(pg) {
  if (pg.task) { try { pg.task.cancel(); } catch {} pg.task = null; }
  pg.key = null;
  pg.canvas.width = 1; pg.canvas.height = 1;
}

function updatePageInfo() {
  if (!S.pages.length) return;
  const v = $('viewer').getBoundingClientRect();
  const mid = v.top + v.height / 2;
  let best = 0, bestD = Infinity;
  S.pages.forEach((p, i) => {
    const r = p.el.getBoundingClientRect();
    const d = Math.abs((r.top + r.bottom) / 2 - mid);
    if (d < bestD) { bestD = d; best = i; }
  });
  $('pageInfo').textContent = `Page ${best + 1}/${S.pages.length}`;
}
let scrollRaf = 0;
$('viewer').addEventListener('scroll', () => {
  if (scrollRaf) return;
  scrollRaf = requestAnimationFrame(() => { scrollRaf = 0; updatePageInfo(); });
}, { passive: true });

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (S.pdf) { computeBaseWidth(); applyWidth(); } }, 150);
});

/* ------------------------------------------------- pose des éléments */
const DEFAULT_W = { signature: 0.30, initials: 0.10, stamp: 0.22 };

function arm(payload) {
  S.armed = payload;
  document.body.classList.add('armed');
  $('hint').hidden = false;
  $('hintText').textContent = "Touchez la page à l'endroit voulu";
  document.querySelectorAll('.tool[data-tool]').forEach((b) => b.classList.toggle('active', b.dataset.tool === payload.kind));
}
function cancelArm() {
  S.armed = null;
  document.body.classList.remove('armed');
  $('hint').hidden = true;
  document.querySelectorAll('.tool.active').forEach((b) => b.classList.remove('active'));
}

function onPageClick(ev, pg) {
  if (S.armed) {
    const r = pg.el.getBoundingClientRect();
    placeItem(pg, (ev.clientX - r.left) / r.width, (ev.clientY - r.top) / r.height);
    return;
  }
  if (!ev.target.closest('.item')) select(null);
}

function itemFh(it) {
  const pg = S.pages[it.page];
  return (it.fw * pg.wPt / it.ratio) / pg.hPt;
}

function placeItem(pg, cx, cy) {
  const a = S.armed;
  let fw = a.heightPt ? (a.heightPt * a.ratio) / pg.wPt : (DEFAULT_W[a.kind] || 0.25);
  fw = clamp(fw, 0.03, 0.95);
  let fh = (fw * pg.wPt / a.ratio) / pg.hPt;
  if (fh > 0.5) { fw *= 0.5 / fh; fh = 0.5; }
  const it = {
    id: nextId++,
    page: S.pages.indexOf(pg),
    kind: a.kind,
    src: a.src,
    ratio: a.ratio,
    fw,
    fx: clamp(cx - fw / 2, 0, 1 - fw),
    fy: clamp(cy - fh / 2, 0, 1 - fh),
  };
  S.items.push(it);
  S.dirty = true;
  mountItem(it);
  select(it);
  cancelArm();
  toast('Glissez pour déplacer, tirez le point bleu pour agrandir.', 3500);
}

function mountItem(it) {
  const pg = S.pages[it.page];
  const el = document.createElement('div');
  el.className = 'item';
  el.dataset.id = String(it.id);
  const img = document.createElement('img');
  img.src = it.src;
  img.alt = it.kind;
  img.draggable = false;
  const del = document.createElement('button');
  del.className = 'del';
  del.type = 'button';
  del.textContent = '×';
  del.setAttribute('aria-label', 'Supprimer');
  const handle = document.createElement('div');
  handle.className = 'handle';
  el.append(img, del, handle);
  pg.layer.append(el);
  it.el = el;
  layoutItem(it);

  del.addEventListener('pointerdown', (e) => e.stopPropagation());
  del.addEventListener('click', (e) => { e.stopPropagation(); removeItem(it); });

  // déplacement
  el.addEventListener('pointerdown', (e) => {
    if (e.target === handle || e.target === del) return;
    e.preventDefault();
    select(it);
    const rect = pg.el.getBoundingClientRect();
    const sx = e.clientX, sy = e.clientY, ox = it.fx, oy = it.fy;
    const fh = itemFh(it);
    el.setPointerCapture(e.pointerId);
    el.style.cursor = 'grabbing';
    const move = (m) => {
      it.fx = clamp(ox + (m.clientX - sx) / rect.width, 0, 1 - it.fw);
      it.fy = clamp(oy + (m.clientY - sy) / rect.height, 0, 1 - fh);
      layoutItem(it);
    };
    const up = () => {
      el.releasePointerCapture?.(e.pointerId);
      el.style.cursor = '';
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
      S.dirty = true;
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  });

  // redimensionnement (proportionnel)
  handle.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    e.stopPropagation();
    select(it);
    const rect = pg.el.getBoundingClientRect();
    const sx = e.clientX, ow = it.fw;
    const maxByW = 1 - it.fx;
    const maxByH = (1 - it.fy) * pg.hPt * it.ratio / pg.wPt;
    handle.setPointerCapture(e.pointerId);
    const move = (m) => {
      it.fw = clamp(ow + (m.clientX - sx) / rect.width, 0.03, Math.min(maxByW, maxByH));
      layoutItem(it);
    };
    const up = () => {
      handle.releasePointerCapture?.(e.pointerId);
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      handle.removeEventListener('pointercancel', up);
      S.dirty = true;
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
    handle.addEventListener('pointercancel', up);
  });
}

function layoutItem(it) {
  const el = it.el;
  el.style.left = (it.fx * 100) + '%';
  el.style.top = (it.fy * 100) + '%';
  el.style.width = (it.fw * 100) + '%';
  el.style.height = (itemFh(it) * 100) + '%';
}

function select(it) {
  if (S.selected && S.selected.el) S.selected.el.classList.remove('selected');
  S.selected = it;
  if (it) {
    it.el.classList.add('selected');
    // l'élément sélectionné passe au premier plan
    it.el.parentElement.append(it.el);
  }
}
function removeItem(it) {
  it.el.remove();
  S.items = S.items.filter((x) => x !== it);
  if (S.selected === it) S.selected = null;
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && S.armed) cancelArm();
  if ((e.key === 'Delete' || e.key === 'Backspace') && S.selected && !/INPUT|TEXTAREA/.test(document.activeElement.tagName) && !document.querySelector('dialog[open]')) {
    e.preventDefault();
    removeItem(S.selected);
  }
});

/* ------------------------------------------------------- outils */
let afterAssetSaved = null; // quoi faire une fois la signature enregistrée

function useTool(kind) {
  if (!S.pdf) { toast("Ouvrez d'abord un document."); return; }
  if (S.armed && S.armed.kind === kind) { cancelArm(); return; }
  if (kind === 'date' || kind === 'text') { openTextDialog(kind); return; }
  const a = assets[kind];
  if (a) { arm({ kind, src: a.src, ratio: a.ratio }); return; }
  afterAssetSaved = kind;
  if (kind === 'stamp') startImport('stamp');
  else openPad(kind);
}

document.querySelectorAll('.tool[data-tool]').forEach((b) => b.addEventListener('click', () => useTool(b.dataset.tool)));
$('hintCancel').addEventListener('click', cancelArm);

/* ------------------------------------------- zone de dessin (signature) */
const pad = { ctx: null, kind: 'signature', ink: false, drawing: false, last: null, mid: null, w: 2.6, penSeen: false, dpr: 1 };

function openPad(kind) {
  pad.kind = kind;
  $('padTitle').textContent = kind === 'initials' ? 'Dessinez votre paraphe' : 'Dessinez votre signature';
  openDlg($('padDialog'));
  requestAnimationFrame(sizePad);
}
function sizePad() {
  const c = $('padCanvas');
  const r = c.getBoundingClientRect();
  pad.dpr = Math.min(window.devicePixelRatio || 1, 3);
  c.width = Math.round(r.width * pad.dpr);
  c.height = Math.round(r.height * pad.dpr);
  pad.ctx = c.getContext('2d');
  pad.ctx.lineCap = 'round';
  pad.ctx.lineJoin = 'round';
  pad.ink = false;
  pad.penSeen = false;
}
function padColor() { return document.querySelector('input[name="padColor"]:checked').value; }
function padPoint(e) {
  const r = $('padCanvas').getBoundingClientRect();
  return { x: (e.clientX - r.left) * pad.dpr, y: (e.clientY - r.top) * pad.dpr };
}
function padWidth(e) {
  const base = pad.w * pad.dpr;
  if (e.pointerType === 'pen' && e.pressure > 0) return base * (0.55 + 0.9 * e.pressure);
  return base;
}
(() => {
  const c = $('padCanvas');
  c.addEventListener('pointerdown', (e) => {
    if (e.pointerType === 'pen') pad.penSeen = true;
    if (e.pointerType === 'touch' && pad.penSeen) return; // rejet de la paume si un stylet est utilisé
    e.preventDefault();
    c.setPointerCapture(e.pointerId);
    pad.drawing = true;
    const p = padPoint(e);
    pad.last = p; pad.mid = p; pad.curW = padWidth(e);
    pad.ctx.fillStyle = padColor();
    pad.ctx.beginPath();
    pad.ctx.arc(p.x, p.y, pad.curW / 2, 0, Math.PI * 2);
    pad.ctx.fill();
    pad.ink = true;
  });
  const draw = (e) => {
    const p = padPoint(e);
    const mid = { x: (pad.last.x + p.x) / 2, y: (pad.last.y + p.y) / 2 };
    pad.curW = pad.curW * 0.6 + padWidth(e) * 0.4;
    pad.ctx.strokeStyle = padColor();
    pad.ctx.lineWidth = pad.curW;
    pad.ctx.beginPath();
    pad.ctx.moveTo(pad.mid.x, pad.mid.y);
    pad.ctx.quadraticCurveTo(pad.last.x, pad.last.y, mid.x, mid.y);
    pad.ctx.stroke();
    pad.last = p; pad.mid = mid;
  };
  c.addEventListener('pointermove', (e) => {
    if (!pad.drawing) return;
    e.preventDefault();
    const evs = e.getCoalescedEvents ? e.getCoalescedEvents() : [];
    if (evs.length) evs.forEach(draw); else draw(e);
  });
  const end = (e) => {
    if (!pad.drawing) return;
    pad.drawing = false;
    try { c.releasePointerCapture(e.pointerId); } catch {}
  };
  c.addEventListener('pointerup', end);
  c.addEventListener('pointercancel', end);
})();

$('padClear').addEventListener('click', () => {
  const c = $('padCanvas');
  pad.ctx.clearRect(0, 0, c.width, c.height);
  pad.ink = false;
});
$('padCancel').addEventListener('click', () => { afterAssetSaved = null; closeDlg($('padDialog')); });
$('padSave').addEventListener('click', () => {
  if (!pad.ink) { toast("Dessinez d'abord, avec le doigt, le stylet ou la souris."); return; }
  const trimmed = trimCanvas($('padCanvas'), Math.round(8 * pad.dpr));
  if (!trimmed) { toast("Dessinez d'abord."); return; }
  const out = limitWidth(trimmed, 800);
  assets[pad.kind] = canvasToAsset(out);
  saveAssets();
  closeDlg($('padDialog'));
  refreshAssets();
  finishAssetFlow(pad.kind);
});
$('padDialog').addEventListener('close', () => { pad.drawing = false; });

function finishAssetFlow(kind) {
  advisePin();
  if (afterAssetSaved === kind && S.pdf) arm({ kind, src: assets[kind].src, ratio: assets[kind].ratio });
  afterAssetSaved = null;
}

/* ----------------------------------------- import d'image (cachet, etc.) */
let importKind = 'stamp';
let importImg = null;

function startImport(kind) {
  importKind = kind;
  $('importInput').value = '';
  $('importInput').click();
}
$('importInput').addEventListener('change', async () => {
  const f = $('importInput').files[0];
  if (!f) { afterAssetSaved = null; return; }
  try {
    importImg = await loadImage(await fileToDataURL(f));
  } catch { toast('Image illisible.'); afterAssetSaved = null; return; }
  $('importTitle').textContent = { stamp: 'Importer le cachet', signature: 'Importer la signature', initials: 'Importer le paraphe' }[importKind];
  $('importRemoveBg').checked = true;
  openDlg($('importDialog'));
  drawImportPreview();
});
$('importRemoveBg').addEventListener('change', drawImportPreview);

function processImported(removeBg) {
  const k = Math.min(1, 900 / Math.max(importImg.naturalWidth, importImg.naturalHeight));
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(importImg.naturalWidth * k));
  c.height = Math.max(1, Math.round(importImg.naturalHeight * k));
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(importImg, 0, 0, c.width, c.height);
  if (removeBg) {
    const im = ctx.getImageData(0, 0, c.width, c.height);
    const d = im.data;
    for (let i = 0; i < d.length; i += 4) {
      const lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
      const a = lum >= 235 ? 0 : lum <= 170 ? 255 : ((235 - lum) / 65) * 255;
      d[i + 3] = Math.min(d[i + 3], a);
    }
    ctx.putImageData(im, 0, 0);
  }
  return trimCanvas(c, 6) || c;
}
function drawImportPreview() {
  if (!importImg) return;
  const out = processImported($('importRemoveBg').checked);
  const prev = $('importCanvas');
  prev.width = out.width; prev.height = out.height;
  prev.getContext('2d').drawImage(out, 0, 0);
}
$('importCancel').addEventListener('click', () => { afterAssetSaved = null; closeDlg($('importDialog')); });
$('importSave').addEventListener('click', () => {
  const out = limitWidth(processImported($('importRemoveBg').checked), 800);
  assets[importKind] = canvasToAsset(out);
  saveAssets();
  closeDlg($('importDialog'));
  refreshAssets();
  finishAssetFlow(importKind);
});

/* ------------------------------------------------------ texte / date */
let textKind = 'text';

function renderText(text, color) {
  const lines = text.split('\n').map((l) => l.trimEnd());
  const size = 56, lh = Math.round(size * 1.25), padPx = 8;
  const font = `600 ${size}px "Segoe UI", Roboto, Helvetica, Arial, sans-serif`;
  const m = document.createElement('canvas').getContext('2d');
  m.font = font;
  const w = Math.ceil(Math.max(...lines.map((l) => m.measureText(l).width), 10)) + padPx * 2;
  const h = lh * lines.length + padPx * 2;
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const ctx = c.getContext('2d');
  ctx.font = font;
  ctx.fillStyle = color;
  ctx.textBaseline = 'middle';
  lines.forEach((l, i) => ctx.fillText(l, padPx, padPx + lh * i + lh / 2));
  return { src: c.toDataURL('image/png'), ratio: w / h, lines: lines.length };
}
function textColor() { return document.querySelector('input[name="textColor"]:checked').value; }
function updateTextPreview() {
  const t = $('textInput').value.trim();
  const img = $('textPreview');
  if (!t) { img.removeAttribute('src'); img.style.visibility = 'hidden'; return; }
  img.style.visibility = 'visible';
  img.src = renderText(t, textColor()).src;
}
function openTextDialog(kind) {
  textKind = kind;
  $('textTitle').textContent = kind === 'date' ? 'Ajouter la date' : 'Ajouter du texte';
  $('textInput').value = kind === 'date' ? todayFr() : '';
  openDlg($('textDialog'));
  updateTextPreview();
  if (kind === 'text') $('textInput').focus();
}
$('textInput').addEventListener('input', updateTextPreview);
document.querySelectorAll('input[name="textColor"]').forEach((r) => r.addEventListener('change', updateTextPreview));
$('textChips').addEventListener('click', (e) => {
  const b = e.target.closest('.chip');
  if (!b) return;
  $('textInput').value = b.dataset.fill === 'date' ? todayFr() : b.dataset.fill;
  updateTextPreview();
});
$('textCancel').addEventListener('click', () => closeDlg($('textDialog')));
$('textSave').addEventListener('click', () => {
  const t = $('textInput').value.trim();
  if (!t) { toast('Écrivez un texte.'); return; }
  const r = renderText(t, textColor());
  closeDlg($('textDialog'));
  arm({ kind: textKind, src: r.src, ratio: r.ratio, heightPt: 15 * r.lines });
});

/* ------------------------------------------------- mes signatures */
const ASSET_LABELS = { signature: 'Signature', initials: 'Paraphe', stamp: 'Cachet' };

function refreshAssets() {
  const host = $('assetsList');
  host.replaceChildren();
  for (const kind of ['signature', 'initials', 'stamp']) {
    const a = assets[kind];
    const card = document.createElement('div');
    card.className = 'asset';
    const thumb = document.createElement('div');
    thumb.className = 'thumb';
    if (a) { const i = document.createElement('img'); i.src = a.src; i.alt = ASSET_LABELS[kind]; thumb.append(i); }
    else { const em = document.createElement('em'); em.textContent = 'Pas encore enregistré'; thumb.append(em); }
    const right = document.createElement('div');
    const h = document.createElement('h4');
    h.textContent = ASSET_LABELS[kind];
    const row = document.createElement('div');
    row.className = 'row';
    const mk = (label, fn, cls = '') => {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'btn ' + cls; b.textContent = label;
      b.addEventListener('click', fn);
      row.append(b);
    };
    if (kind !== 'stamp') mk(a ? 'Redessiner' : 'Dessiner', () => { closeDlg($('assetsDialog')); afterAssetSaved = null; openPad(kind); });
    mk('Importer une photo', () => { closeDlg($('assetsDialog')); afterAssetSaved = null; startImport(kind); });
    if (a) mk('Supprimer', () => { delete assets[kind]; saveAssets(); refreshAssets(); }, 'danger');
    right.append(h, row);
    card.append(thumb, right);
    host.append(card);
  }
  refreshSecurityUI();
}
$('btnAssets').addEventListener('click', () => { refreshAssets(); openDlg($('assetsDialog')); });

/* ----------------------------------------------------------- export */
// Convertit un point de la page affichée (u vers la droite, v vers le bas, en points)
// vers l'espace utilisateur du PDF, en tenant compte de la rotation et du cadrage de la page.
function toUserSpace(pg, u, v) {
  const [x0, y0, x1, y1] = pg.view;
  const vw = x1 - x0, vh = y1 - y0;
  switch (pg.rotate) {
    case 90:  return [x0 + v, y0 + u];
    case 180: return [x0 + vw - u, y0 + v];
    case 270: return [x0 + vw - v, y0 + vh - u];
    default:  return [x0 + u, y1 - v];
  }
}

async function buildSignedPdf() {
  const doc = await PDFDocument.load(S.bytes.slice(), { ignoreEncryption: true });
  const cache = new Map();
  for (const it of S.items) {
    const pg = S.pages[it.page];
    const page = doc.getPage(it.page);
    let img = cache.get(it.src);
    if (!img) { img = await doc.embedPng(it.src); cache.set(it.src, img); }
    const wPt = it.fw * pg.wPt;
    const hPt = wPt / it.ratio;
    const u = it.fx * pg.wPt;
    const v = it.fy * pg.hPt + hPt; // coin bas-gauche de l'élément, vu à l'écran
    const [x, y] = toUserSpace(pg, u, v);
    page.drawImage(img, { x, y, width: wPt, height: hPt, rotate: degrees(pg.rotate) });
  }
  return await doc.save();
}

async function doExport() {
  if (!S.pdf) return;
  if (!S.items.length && !confirm("Aucune signature n'a été posée. Exporter quand même ?")) return;
  busy(true, 'Création du PDF signé…');
  try {
    const bytes = await buildSignedPdf();
    S.exportBlob = new Blob([bytes], { type: 'application/pdf' });
    S.exportName = `${S.name}-signé.pdf`;
    const mb = (S.exportBlob.size / 1048576).toFixed(2).replace('.', ',');
    $('exportInfo').textContent = `${S.exportName} · ${mb} Mo · ${S.items.length} élément(s) posé(s)`;
    const canShare = !!(navigator.canShare && navigator.canShare({ files: [new File([S.exportBlob], S.exportName, { type: 'application/pdf' })] }));
    $('exportShare').hidden = !canShare;
    S.dirty = false;
    openDlg($('exportDialog'));
  } catch (e) {
    console.error(e);
    toast("L'export a échoué. Ce PDF est peut-être protégé ou endommagé.", 5000);
  } finally {
    busy(false);
  }
}
$('exportDownload').addEventListener('click', () => {
  if (!S.exportBlob) return;
  const url = URL.createObjectURL(S.exportBlob);
  const a = document.createElement('a');
  a.href = url; a.download = S.exportName;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
});
$('exportShare').addEventListener('click', async () => {
  if (!S.exportBlob) return;
  try {
    await navigator.share({ files: [new File([S.exportBlob], S.exportName, { type: 'application/pdf' })], title: S.exportName });
  } catch (e) {
    if (e && e.name !== 'AbortError') toast('Partage impossible : utilisez Télécharger.');
  }
});

/* --------------------------------------------------- boutons / divers */
const openPicker = () => { $('fileInput').value = ''; $('fileInput').click(); };
$('btnOpen').addEventListener('click', openPicker);
$('btnOpen2').addEventListener('click', openPicker);
$('fileInput').addEventListener('change', () => handleFile($('fileInput').files[0]));
$('btnExport').addEventListener('click', doExport);
$('zoomIn').addEventListener('click', () => setZoom(S.zoom + 0.25));
$('zoomOut').addEventListener('click', () => setZoom(S.zoom - 0.25));
$('btnHelp').addEventListener('click', () => openDlg($('helpDialog')));

// glisser-déposer (PC)
const viewer = $('viewer');
['dragenter', 'dragover'].forEach((t) => viewer.addEventListener(t, (e) => { e.preventDefault(); viewer.classList.add('dragover'); }));
['dragleave', 'drop'].forEach((t) => viewer.addEventListener(t, (e) => { e.preventDefault(); viewer.classList.remove('dragover'); }));
viewer.addEventListener('drop', (e) => { const f = e.dataTransfer?.files?.[0]; if (f) handleFile(f); });

window.addEventListener('beforeunload', (e) => {
  if (S.dirty && S.items.length) { e.preventDefault(); e.returnValue = ''; }
});

// installation (Chrome / Edge / Android)
let installEvt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  installEvt = e;
  $('btnInstall').hidden = false;
});
$('btnInstall').addEventListener('click', async () => {
  if (!installEvt) return;
  installEvt.prompt();
  await installEvt.userChoice.catch(() => {});
  installEvt = null;
  $('btnInstall').hidden = true;
});
window.addEventListener('appinstalled', () => { $('btnInstall').hidden = true; });

// fonctionnement hors connexion
if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
  navigator.serviceWorker.register('./sw.js').catch((e) => console.warn('Service worker non enregistré', e));
}

// démarrage : si un code PIN existe, l'application commence verrouillée
if (sec) lock();

// accès de test (utilisé par les tests automatiques, sans effet pour l'utilisateur)
window.__signapro = { S, assets };
