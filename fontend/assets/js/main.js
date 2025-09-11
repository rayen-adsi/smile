// ===============================
// Smile Tunisia - main.js
// - WhatsApp helper
// - Trust cards photo slideshows
// ===============================

function openWhatsApp() {
  const phone = document.body.dataset.whatsapp || "";
  const msg = encodeURIComponent("Bonjour, je souhaite des informations pour un devis dentaire.");
  const url = `https://wa.me/${phone}?text=${msg}`;
  window.open(url, "_blank");
}

/**
 * Card slideshows for the "Centre Jasmin" section.
 * Each .trust-card must have: data-photos="/path/one.jpg, /path/two.jpg, ..."
 * We inject two layers and cross-fade them on hover/focus (tap on mobile).
 */
function initTrustCardSlides() {
  const cards = document.querySelectorAll("#trust .trust-card[data-photos]");
  const CYCLE_MS = 2200; // change speed if you want

  cards.forEach((card) => {
    // Parse URLs
    const urls = (card.dataset.photos || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (!urls.length) return;

    // Preload to avoid flicker
    urls.forEach((u) => {
      const im = new Image();
      im.src = u;
    });

    // Build slideshow layers
    const box = document.createElement("div");
    box.className = "photo-slideshow";

    const a = document.createElement("div");
    a.className = "ph ph-a";

    const b = document.createElement("div");
    b.className = "ph ph-b";

    box.append(a, b);
    card.prepend(box); // behind text (CSS keeps text on top)

    let i = 0;
    let showingA = true;
    let timer = null;

    function showNext() {
      const url = urls[i % urls.length];
      i++;

      const showEl = showingA ? a : b;
      const hideEl = showingA ? b : a;

      showEl.style.backgroundImage = `url('${url}')`;
      showEl.classList.add("show");
      hideEl.classList.remove("show");

      showingA = !showingA;
    }

    function start() {
      if (timer) return; // already running
      card.classList.add("active");
      showNext();
      if (urls.length > 1) {
        timer = setInterval(showNext, CYCLE_MS);
      }
    }

    function stop() {
      card.classList.remove("active");
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      a.classList.remove("show");
      b.classList.remove("show");
    }

    // Desktop
    card.addEventListener("mouseenter", start);
    card.addEventListener("focus", start);
    card.addEventListener("mouseleave", stop);
    card.addEventListener("blur", stop);

    // Mobile: first tap starts, tap outside stops
    card.addEventListener("touchstart", () => start(), { passive: true });
    document.addEventListener(
      "touchstart",
      (e) => {
        if (!card.contains(e.target)) stop();
      },
      { passive: true }
    );
  });
}

// Init
document.addEventListener("DOMContentLoaded", () => {
  initTrustCardSlides();
});
function initWhyInteractive(){
  const sec = document.querySelector('#why');
  if (!sec) return;

  const cards = sec.querySelectorAll('.point[data-theme]');

  const activate = (name, el) => {
    sec.classList.remove('theme-expertise','theme-tech','theme-care');
    if (name) sec.classList.add(`theme-${name}`);
    cards.forEach(c => c.classList.toggle('active', c === el));
  };

  const reset = () => {
    sec.classList.remove('theme-expertise','theme-tech','theme-care');
    cards.forEach(c => c.classList.remove('active'));
  };

  cards.forEach(card => {
    const t = card.dataset.theme;
    card.addEventListener('mouseenter', () => activate(t, card));
    card.addEventListener('focusin',   () => activate(t, card));
    card.addEventListener('mouseleave', reset);
    card.addEventListener('focusout',   reset);
  });

  // Mobile: tap to activate, tap outside to reset
  sec.addEventListener('touchstart', (e) => {
    const c = e.target.closest('.point[data-theme]');
    if (c) activate(c.dataset.theme, c);
  }, { passive:true });

  document.addEventListener('touchstart', (e) => {
    if (!sec.contains(e.target)) reset();
  }, { passive:true });
}

document.addEventListener('DOMContentLoaded', () => {
  initWhyInteractive();
});
function initClinicMosaic(){
  const mosaic = document.getElementById('clinicMosaic');
  const lb     = document.getElementById('lbClinic');
  if (!mosaic || !lb) return;

  const tiles = Array.from(mosaic.querySelectorAll('.tile'));
  const img   = lb.querySelector('.lb-img');
  const prev  = lb.querySelector('.lb-prev');
  const next  = lb.querySelector('.lb-next');
  const close = lb.querySelector('.lb-close');

  const sources = tiles.map(t => t.dataset.src);
  let idx = 0;

  const open = (i) => {
    idx = (i + sources.length) % sources.length;
    img.src = sources[idx];
    lb.hidden = false;
    document.body.style.overflow = 'hidden';
  };
  const show = (n) => { idx = (idx + n + sources.length) % sources.length; img.src = sources[idx]; };
  const hide = () => { lb.hidden = true; img.src = ''; document.body.style.overflow = ''; };

  tiles.forEach((t, i) => t.addEventListener('click', () => open(i)));
  prev.addEventListener('click', () => show(-1));
  next.addEventListener('click', () => show(1));
  close.addEventListener('click', hide);
  lb.addEventListener('click', (e) => { if (e.target === lb) hide(); });
  document.addEventListener('keydown', (e) => {
    if (lb.hidden) return;
    if (e.key === 'Escape') hide();
    if (e.key === 'ArrowLeft') show(-1);
    if (e.key === 'ArrowRight') show(1);
  });
}
document.addEventListener('DOMContentLoaded', initClinicMosaic);
// --- RESULTS: Before/After slider (arrows + dots + handle) ---
function initResultsBeforeAfter () {
  const vp = document.querySelector('#results .ba-viewport');
  if (!vp || vp.dataset.inited) return;      // prevent double init
  vp.dataset.inited = '1';

  const track  = vp.querySelector('.ba-track');
  const slides = [...vp.querySelectorAll('.ba-slide')];
  const prev   = vp.querySelector('.ba-prev');
  const next   = vp.querySelector('.ba-next');
  const dots   = [...vp.querySelectorAll('.ba-dot')];

  let i = 0;

  const go = (idx, { immediate = false } = {}) => {
    i = (idx + slides.length) % slides.length;
    track.style.transition = immediate ? 'none' : '';
    track.style.transform  = `translateX(${-i * 100}%)`;

    dots.forEach((d, k) => {
      const on = k === i;
      d.classList.toggle('is-active', on);
      d.setAttribute('aria-selected', on);
      d.tabIndex = on ? 0 : -1;
    });
  };

  // click helpers (never bubble)
  const safe = fn => e => { e.preventDefault(); e.stopPropagation(); fn(); };

  if (prev) prev.addEventListener('click', safe(() => go(i - 1)));
  if (next) next.addEventListener('click', safe(() => go(i + 1)));
  dots.forEach((d, k) => d.addEventListener('click', safe(() => go(k))));

  // per-slide handle drag (no bubbling to viewport)
  vp.querySelectorAll('.ba-frame').forEach(frame => {
    const handle = frame.querySelector('.ba__handle');

    const setPos = p => {
      p = Math.max(0, Math.min(100, p));
      frame.style.setProperty('--pos', p + '%');
      if (handle) handle.setAttribute('aria-valuenow', Math.round(p));
    };

    const move = clientX => {
      const r = frame.getBoundingClientRect();
      setPos(((clientX - r.left) / r.width) * 100);
    };

    const startDrag = ev => {
      ev.preventDefault();
      ev.stopPropagation();                            // << don’t bubble
      const point = ev.touches?.[0] || ev;
      move(point.clientX);

      const mm = e => move((e.touches?.[0] || e).clientX);
      const up = () => {
        window.removeEventListener('mousemove', mm);
        window.removeEventListener('touchmove', mm);
        window.removeEventListener('mouseup', up);
        window.removeEventListener('touchend', up);
      };
      window.addEventListener('mousemove', mm);
      window.addEventListener('touchmove', mm, { passive: false });
      window.addEventListener('mouseup', up);
      window.addEventListener('touchend', up);
    };

    handle?.addEventListener('mousedown', startDrag);
    handle?.addEventListener('touchstart', startDrag, { passive: false });

    handle?.addEventListener('keydown', e => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        const cur = parseFloat(getComputedStyle(frame).getPropertyValue('--pos')) || 50;
        setPos(cur + (e.key === 'ArrowLeft' ? -3 : 3));
      }
    });
  });

  go(0, { immediate: true });
}

// call once (keep this near the end of main.js)
document.addEventListener('DOMContentLoaded', () => {
  initResultsBeforeAfter();
});
function initTourismCarousel () {
  // Works for the home section (#tourism …) and this guide page (.hero-tourism …)
  const vp = document.querySelector('#tourism .tourism-viewport, .hero-tourism .tourism-viewport');
  if (!vp || vp.dataset.inited) return;
  vp.dataset.inited = '1';

  const track  = vp.querySelector('.tourism-track') || vp;
  const slides = Array.from(vp.querySelectorAll('.t-slide'));
  const prev   = vp.querySelector('.t-prev');
  const next   = vp.querySelector('.t-next');
  const dots   = Array.from(vp.querySelectorAll('.t-dot'));

  // --- Set background on .t-bg directly (no CSS var dependency) + preload
  slides.forEach((s, idx) => {
    const bg  = s.querySelector('.t-bg');
    let src   = s.getAttribute('data-img') || "";
    if (!src) {
      const inline = s.getAttribute('style') || "";
      const m = inline.match(/--img:\s*url\((['"]?)(.*?)\1\)/i);
      if (m && m[2]) src = m[2];
    }
    if (!src) { console.warn('[tourism] Slide', idx + 1, 'has no image.'); return; }

    const im = new Image();
    im.onload  = () => { if (bg) bg.style.backgroundImage = `url("${src}")`; };
    im.onerror = () => console.warn('[tourism] Image not found:', src);
    im.src = src;
  });

  // If there’s no carousel UI (like on this guide page), we’re done.
  if (!vp.querySelector('.t-prev') && !vp.querySelector('.t-next') && dots.length === 0) return;

  // --- Carousel behavior (only runs if controls are present)
  let i = 0;
  let autoplayId = null;
  const AUTOPLAY_MS = 3000;

  const setActiveDot = () => {
    dots.forEach((d, k) => {
      const on = k === i;
      d.classList.toggle('is-active', on);
      d.setAttribute('aria-selected', on ? 'true' : 'false');
      d.tabIndex = on ? 0 : -1;
    });
  };

  const go = (idx, { immediate = false } = {}) => {
    i = (idx + slides.length) % slides.length;
    const x = -i * vp.clientWidth;
    track.style.transition = immediate ? 'none' : '';
    track.style.transform  = `translate3d(${x}px,0,0)`;
    setActiveDot();
  };

  // keep alignment on resize
  window.addEventListener('resize', () => go(i, { immediate: true }));

  // autoplay only when visible
  const schedule = () => {
    clearTimeout(autoplayId);
    autoplayId = setTimeout(() => { go(i + 1); schedule(); }, AUTOPLAY_MS);
  };
  const pause = () => { clearTimeout(autoplayId); autoplayId = null; };

  const io = new IntersectionObserver((entries) => {
    entries.forEach(e => e.isIntersecting ? schedule() : pause());
  }, { threshold: 0.5 });
  io.observe(vp);

  const clickSafe = fn => e => { e.preventDefault(); e.stopPropagation(); fn(); schedule(); };
  if (prev) prev.addEventListener('click', clickSafe(() => go(i - 1)));
  if (next) next.addEventListener('click', clickSafe(() => go(i + 1)));
  dots.forEach((d, k) => d.addEventListener('click', clickSafe(() => go(k))));

  // swipe
  let startX = 0, curX = 0, swiping = false;
  const thresholdPx = () => Math.min(120, vp.clientWidth * 0.15);

  const down = e => {
    swiping = true;
    startX = curX = (e.touches?.[0] || e).clientX;
    track.style.transition = 'none';
    pause();
  };
  const move = e => {
    if (!swiping) return;
    curX = (e.touches?.[0] || e).clientX;
    const dx = curX - startX;
    const x = (-i * vp.clientWidth) + dx;
    track.style.transform = `translate3d(${x}px,0,0)`;
  };
  const up = () => {
    if (!swiping) return;
    swiping = false;
    track.style.transition = '';
    const dx = curX - startX;
    Math.abs(dx) > thresholdPx() ? go(i + (dx < 0 ? 1 : -1)) : go(i);
    schedule();
  };

  vp.addEventListener('mousedown', down);
  vp.addEventListener('mousemove', move);
  window.addEventListener('mouseup', up);

  vp.addEventListener('touchstart', down, { passive: true });
  vp.addEventListener('touchmove',  move, { passive: true });
  vp.addEventListener('touchend',   up);

  go(0, { immediate: true });
}
document.addEventListener('DOMContentLoaded', initTourismCarousel);
// Mobile burger menu (no impact on desktop)
(function(){
  const burger = document.getElementById('burger');
  const links  = document.getElementById('navLinks');
  if (!burger || !links) return;

  const setOpen = (open) => {
    document.body.classList.toggle('menu-open', open);
    burger.setAttribute('aria-expanded', String(open));
  };

  burger.addEventListener('click', () => {
    const open = burger.getAttribute('aria-expanded') === 'true';
    setOpen(!open);
  });

  // Close when a link is clicked
  links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => setOpen(false)));

  // Close with Escape
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') setOpen(false); });
})();

(function(){
  const v = document.getElementById('clinicVideo');
  const o = document.getElementById('vOverlay');
  if(!v || !o) return;

  const setPlaying = (is) => {
    v.closest('.trust-video-card').classList.toggle('playing', is);
  };

  // overlay click starts/pauses video
  o.addEventListener('click', () => {
    if (v.paused) { v.play().catch(()=>{}); setPlaying(true); }
    else { v.pause(); setPlaying(false); }
  });

  // keep overlay state in sync if user uses native controls
  v.addEventListener('play',  () => setPlaying(true));
  v.addEventListener('pause', () => setPlaying(false));

  // Optional: auto-pause when scrolled away
  const io = new IntersectionObserver(es=>{
    es.forEach(e=>{
      if(!e.isIntersecting && !v.paused){ v.pause(); setPlaying(false); }
    });
  },{threshold:.2});
  io.observe(v);
})();
// One initializer for both TRUST (.trust-card) and QUALIFS (.qcard)
// - TRUST cards: cycle every 2.2s while hovered
// - QUALIFS cards: show one frame per hover (step to next each time)
// - On mouseleave/focusout: hide the photo (clean fade-out)
function initAllCardSlides() {
  const cards = document.querySelectorAll(
    ".trust-card[data-photos], .qcard[data-photos]"
  );
  const CYCLE_MS = 2200;

  cards.forEach((card) => {
    const urls = (card.dataset.photos || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!urls.length) return;

    // Preload
    urls.forEach((u) => { const im = new Image(); im.src = u; });

    // Build layers
    const box = document.createElement("div");
    box.className = "photo-slideshow";
    const a = document.createElement("div"); a.className = "ph ph-a";
    const b = document.createElement("div"); b.className = "ph ph-b";
    box.append(a, b);
    card.prepend(box);

    let i = 0;
    let showingA = true;
    let timer = null;

    const showNext = () => {
      const url = urls[i % urls.length]; i++;
      const showEl = showingA ? a : b;
      const hideEl = showingA ? b : a;
      showEl.style.backgroundImage = `url("${url}")`;
      showEl.classList.add("show");
      hideEl.classList.remove("show");
      showingA = !showingA;
    };

    const start = () => {
      // Always start by revealing one frame
      card.classList.add("active");
      showNext();

      // TRUST: auto-cycle while hovered
      if (card.closest("#trust") && !timer && urls.length > 1) {
        timer = setInterval(showNext, CYCLE_MS);
      }
      // QUALIFS: no timer -> “step” each time you hover; nothing else needed
    };

    const stop = () => {
      card.classList.remove("active");
      if (timer) { clearInterval(timer); timer = null; }
      a.classList.remove("show");
      b.classList.remove("show");
    };

    // Desktop
    card.addEventListener("mouseenter", start);
    card.addEventListener("focusin", start);
    card.addEventListener("mouseleave", stop);
    card.addEventListener("focusout", stop);

    // Mobile
    card.addEventListener("touchstart", start, { passive: true });
    document.addEventListener("touchstart", (e) => {
      if (!card.contains(e.target)) stop();
    }, { passive: true });
  });
}

document.addEventListener("DOMContentLoaded", initAllCardSlides);
// Generic hover slideshow maker (used by Trust + Why)
function initWhyPhotos(){
  const cards = document.querySelectorAll('#why .point[data-photos]');
  const CYCLE = 2200;

  cards.forEach(card => {
    if (card.dataset.slideshowInit === '1') {
      // Clean up any accidental duplicates from earlier runs
      card.querySelectorAll('.photo-slideshow').forEach(n => n.remove());
    }
    card.dataset.slideshowInit = '1';

    const urls = (card.dataset.photos || '')
      .split(',').map(s => s.trim()).filter(Boolean);
    if (!urls.length) return;

    // Preload
    urls.forEach(u => { const im = new Image(); im.src = u; });

    // Build a single slideshow container
    const box = document.createElement('div'); box.className = 'photo-slideshow';
    const a = document.createElement('div'); a.className = 'ph ph-a';
    const b = document.createElement('div'); b.className = 'ph ph-b';
    box.append(a, b);
    card.prepend(box);

    let i = 0, useA = true, timer = null;

    const showNext = () => {
      const url = urls[i++ % urls.length];
      const showEl = useA ? a : b;
      const hideEl = useA ? b : a;
      showEl.style.backgroundImage = `url("${url}")`;
      showEl.classList.add('show');
      hideEl.classList.remove('show');       // make sure the other one is hidden
      useA = !useA;
    };

    const start = () => {
      if (timer) return;
      showNext();
      if (urls.length > 1) timer = setInterval(showNext, CYCLE);
    };

    const stop = () => {
      if (timer){ clearInterval(timer); timer = null; }
      a.classList.remove('show');
      b.classList.remove('show');
      // hide the whole photo layer between hovers (prevents “stacking” look)
      box.style.opacity = '0';
      // force reflow so next hover re-fades cleanly
      void box.offsetHeight;
      box.style.opacity = '';
    };

    card.addEventListener('mouseenter', start);
    card.addEventListener('focusin',   start);
    card.addEventListener('mouseleave', stop);
    card.addEventListener('focusout',   stop);

    // Mobile: tap to start; tap outside to stop
    card.addEventListener('touchstart', start, { passive:true });
    document.addEventListener('touchstart', e => {
      if (!card.contains(e.target)) stop();
    }, { passive:true });
  });
}
document.addEventListener('DOMContentLoaded', initWhyPhotos);
