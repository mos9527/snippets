// ==UserScript==
// @name         抖音视频链接提取器 (Douyin VOD Extractor)
// @namespace    https://github.com/local/douyin-vod-extractor
// @version      1.0.0
// @description  在抖音页面提取当前视频真实播放链接（从接口/请求中恢复，非 blob），提供悬浮按钮复制链接并下载最佳源。
// @author       you
// @match        https://www.douyin.com/*
// @match        https://*.douyin.com/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  const STORE = new Map(); // awemeId -> { awemeId, desc, author, urls:Set<string>, updatedAt:number }
  const MAX_STORE = 300;
  const BTN_ID = 'dy-vod-extractor-btn';
  const BTN_JUMP_ID = 'dy-vod-jump-btn';

  /* ============================================================
   * 1) 通用工具
   * ============================================================ */
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function toArray(v) {
    return Array.isArray(v) ? v : [];
  }

  function safeJsonParse(text) {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  function unique(arr) {
    return [...new Set(arr.filter(Boolean))];
  }

  function nowTs() {
    return Date.now();
  }

  function getModalIdFromUrl() {
    try {
      return new URL(location.href).searchParams.get('modal_id') || '';
    } catch {
      return '';
    }
  }

  function getVideoIdFromPath() {
    const m = String(location.pathname || '').match(/\/video\/(\d+)/);
    return m ? m[1] : '';
  }

  function getCanonicalVideoUrl() {
    // 弹窗场景优先 modal_id：/video/{modal_id}
    // 非弹窗再回退到当前 path 的 /video/{id}
    const id = getModalIdFromUrl() || getVideoIdFromPath();
    return id ? `${location.origin}/video/${id}` : '';
  }

  function getPrimaryAwemeId() {
    // 与跳转规则保持一致：modal_id 优先
    return getModalIdFromUrl() || getVideoIdFromPath();
  }

  function sanitizeFilename(name) {
    return String(name || 'douyin-video').replace(/[\\/:*?"<>|]/g, '_').slice(0, 120);
  }

  function addRecord(awemeId, payload) {
    if (!awemeId) return;
    const old = STORE.get(awemeId);
    const record = old || {
      awemeId,
      desc: '',
      author: '',
      urls: new Set(),
      updatedAt: nowTs(),
    };

    if (payload.desc) record.desc = payload.desc;
    if (payload.author) record.author = payload.author;
    for (const u of payload.urls || []) {
      if (typeof u === 'string' && /^https?:\/\//.test(u)) record.urls.add(u);
    }
    record.updatedAt = nowTs();
    STORE.set(awemeId, record);

    if (STORE.size > MAX_STORE) {
      const sorted = [...STORE.values()].sort((a, b) => a.updatedAt - b.updatedAt);
      const overflow = STORE.size - MAX_STORE;
      for (let i = 0; i < overflow; i++) STORE.delete(sorted[i].awemeId);
    }
  }

  /* ============================================================
   * 2) 抽取 aweme/video 信息
   * ============================================================ */
  function collectUrlCandidatesFromVideo(videoObj) {
    if (!videoObj || typeof videoObj !== 'object') return [];
    const urls = [];

    const pushUrlList = (node) => {
      if (!node || typeof node !== 'object') return;
      for (const u of toArray(node.url_list)) {
        if (typeof u === 'string') urls.push(u);
      }
      for (const u of toArray(node.compressed_url_list)) {
        if (typeof u === 'string') urls.push(u);
      }
    };

    pushUrlList(videoObj.play_addr);
    pushUrlList(videoObj.play_addr_h264);
    pushUrlList(videoObj.play_addr_265);
    pushUrlList(videoObj.download_addr);
    pushUrlList(videoObj.download_suffix_logo_addr);
    pushUrlList(videoObj.play_addr_lowbr);
    pushUrlList(videoObj.play_addr_lowbr_h264);

    for (const br of toArray(videoObj.bit_rate)) {
      pushUrlList(br.play_addr);
      pushUrlList(br.play_addr_265);
      pushUrlList(br.play_addr_h264);
    }
    return unique(urls);
  }

  function ingestAweme(aweme) {
    if (!aweme || typeof aweme !== 'object') return;
    const awemeId = String(aweme.aweme_id || aweme.group_id || aweme.id || '');
    if (!awemeId) return;
    const desc = String(aweme.desc || aweme.item_title || '').trim();
    const author = String((aweme.author && (aweme.author.nickname || aweme.author.unique_id)) || '').trim();
    const urls = collectUrlCandidatesFromVideo(aweme.video);
    if (!urls.length) return;
    addRecord(awemeId, { desc, author, urls });
  }

  function ingestPayload(json) {
    if (!json || typeof json !== 'object') return;

    // 常见字段
    if (Array.isArray(json.aweme_list)) json.aweme_list.forEach(ingestAweme);
    if (json.aweme_detail && typeof json.aweme_detail === 'object') ingestAweme(json.aweme_detail);
    if (Array.isArray(json.item_list)) json.item_list.forEach(ingestAweme);
    if (json.data && Array.isArray(json.data.aweme_list)) json.data.aweme_list.forEach(ingestAweme);
    if (json.data && json.data.aweme_detail) ingestAweme(json.data.aweme_detail);
  }

  /* ============================================================
   * 3) 网络拦截：fetch / XHR
   * ============================================================ */
  function patchFetch() {
    if (!window.fetch || window.__dyVodFetchPatched) return;
    window.__dyVodFetchPatched = true;
    const rawFetch = window.fetch;

    window.fetch = async function (...args) {
      const res = await rawFetch.apply(this, args);
      try {
        const url = String((args[0] && args[0].url) || args[0] || '');
        if (url.includes('/aweme/') || url.includes('/module/feed') || url.includes('/web/')) {
          const ctype = String(res.headers.get('content-type') || '');
          if (ctype.includes('application/json')) {
            const clone = res.clone();
            clone.text().then((text) => {
              const json = safeJsonParse(text);
              ingestPayload(json);
            }).catch(() => {});
          }
        }
      } catch {}
      return res;
    };
  }

  function patchXHR() {
    if (!window.XMLHttpRequest || window.__dyVodXHRPatched) return;
    window.__dyVodXHRPatched = true;

    const rawOpen = XMLHttpRequest.prototype.open;
    const rawSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__dyVodUrl = typeof url === 'string' ? url : '';
      return rawOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function (...args) {
      this.addEventListener('load', function () {
        try {
          const url = String(this.__dyVodUrl || '');
          if (!(url.includes('/aweme/') || url.includes('/module/feed') || url.includes('/web/'))) return;
          const ctype = String(this.getResponseHeader('content-type') || '');
          if (!ctype.includes('application/json')) return;
          if (typeof this.responseText !== 'string' || !this.responseText) return;
          const json = safeJsonParse(this.responseText);
          ingestPayload(json);
        } catch {}
      });
      return rawSend.apply(this, args);
    };
  }

  /* ============================================================
   * 4) 从页面/性能条目补充候选
   * ============================================================ */
  function collectUrlsFromDomVideo() {
    const out = [];
    document.querySelectorAll('video').forEach((v) => {
      const src = v.currentSrc || v.getAttribute('src') || '';
      if (/^https?:\/\//.test(src)) out.push(src);
      v.querySelectorAll('source').forEach((s) => {
        const u = s.getAttribute('src') || '';
        if (/^https?:\/\//.test(u)) out.push(u);
      });
    });
    return unique(out);
  }

  function collectUrlsFromPerformance() {
    if (!window.performance || !performance.getEntriesByType) return [];
    const entries = performance.getEntriesByType('resource');
    const urls = [];
    for (const e of entries) {
      const name = String(e && e.name || '');
      if (!name) continue;
      if (
        /douyinvod|mime_type=video|\/aweme\/v1\/play\/|\.m3u8(\?|$)|\.mp4(\?|$)|tos-cn-ve-15/i.test(name)
      ) {
        if (/^https?:\/\//.test(name)) urls.push(name);
      }
    }
    return unique(urls).slice(-50);
  }

  function scoreUrl(url) {
    let s = 0;
    if (/mime_type=video_mp4/i.test(url)) s += 30;
    if (/douyinvod/i.test(url)) s += 15;
    if (/play_addr_265|bytevc1|h265/i.test(url)) s += 8;
    if (/watermark=1/i.test(url)) s -= 18;
    if (/download_addr/i.test(url)) s += 6;
    if (/ratio=1080p|1080/.test(url)) s += 8;
    if (/ratio=720p|720/.test(url)) s += 5;
    if (/ratio=540p|540/.test(url)) s += 2;
    if (/aweme\/v1\/play\//.test(url)) s += 4;
    return s;
  }

  function sortUrlsByPriority(urls) {
    return [...urls].sort((a, b) => scoreUrl(b) - scoreUrl(a));
  }

  function collectCurrentAsset() {
    const modalId = getModalIdFromUrl();
    const awemeId = getPrimaryAwemeId();
    const fromStore = awemeId && STORE.get(awemeId);
    const storeUrls = fromStore ? [...fromStore.urls] : [];

    const domUrls = collectUrlsFromDomVideo();
    const perfUrls = collectUrlsFromPerformance();
    const all = sortUrlsByPriority(unique([...storeUrls, ...domUrls, ...perfUrls]));

    return {
      awemeId,
      modalId,
      title: fromStore && fromStore.desc ? fromStore.desc : document.title,
      author: fromStore ? fromStore.author : '',
      urls: all,
      bestUrl: all[0] || '',
      sourceStats: {
        store: storeUrls.length,
        dom: domUrls.length,
        perf: perfUrls.length,
      },
    };
  }

  async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }

  function triggerDownload(url, filename) {
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noreferrer noopener';
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function downloadViaPageRequest(url, filename) {
    // CDN 常见返回 Access-Control-Allow-Origin: *，此时不能带 credentials=include
    // 否则会触发 CORS 拦截：wildcard + credentials 不允许并存。
    const res = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      referrer: location.href,
      referrerPolicy: 'strict-origin-when-cross-origin',
    });
    if (!res.ok) {
      throw new Error('HTTP ' + res.status);
    }
    const blob = await res.blob();
    const objectUrl = URL.createObjectURL(blob);
    try {
      triggerDownload(objectUrl, filename);
    } finally {
      setTimeout(() => URL.revokeObjectURL(objectUrl), 5000);
    }
  }

  function showToast(msg, ms = 2200) {
    const id = 'dy-vod-extractor-toast';
    let el = document.getElementById(id);
    if (!el) {
      el = document.createElement('div');
      el.id = id;
      Object.assign(el.style, {
        position: 'fixed',
        right: '24px',
        bottom: '70px',
        zIndex: 2147483647,
        padding: '8px 12px',
        borderRadius: '10px',
        background: 'rgba(0,0,0,.78)',
        color: '#fff',
        fontSize: '12px',
        lineHeight: '1.4',
        maxWidth: '420px',
        boxShadow: '0 6px 20px rgba(0,0,0,.25)',
        whiteSpace: 'pre-wrap',
      });
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.display = 'block';
    clearTimeout(el.__timer);
    el.__timer = setTimeout(() => {
      el.style.display = 'none';
    }, ms);
  }

  /* ============================================================
   * 5) 悬浮按钮
   * ============================================================ */
  function createButton() {
    if (!document.getElementById(BTN_ID)) {
      const btn = document.createElement('button');
      btn.id = BTN_ID;
      btn.textContent = '提取视频';
      Object.assign(btn.style, {
        position: 'fixed',
        right: '24px',
        bottom: '120px',
        zIndex: 2147483647,
        padding: '10px 16px',
        borderRadius: '999px',
        border: 'none',
        background: 'linear-gradient(135deg,#4c8dff,#6f5bff)',
        color: '#fff',
        fontSize: '14px',
        fontWeight: '600',
        cursor: 'pointer',
        boxShadow: '0 6px 18px rgba(76,141,255,.45)',
        userSelect: 'none',
        transition: 'transform .15s ease, opacity .2s ease',
      });
      btn.onmouseenter = () => (btn.style.transform = 'scale(1.06)');
      btn.onmouseleave = () => (btn.style.transform = 'scale(1)');

      const setBusy = (text) => {
        btn.disabled = !!text;
        btn.style.opacity = text ? '0.86' : '1';
        btn.style.cursor = text ? 'default' : 'pointer';
        btn.textContent = text || '提取视频';
      };

      btn.addEventListener('click', async () => {
        if (btn.disabled) return;
        setBusy('提取中…');
        try {
          // 等待一个小窗口，给拦截器一点时间收集当页数据
          await sleep(120);
          const asset = collectCurrentAsset();

          if (!asset.urls.length) {
            showToast(
              '未找到视频链接。\n请先打开一个视频详情页（URL 含 modal_id），并等待视频开始播放后重试。',
              3200
            );
            setBusy('');
            return;
          }

          const text = [
            `aweme_id=${asset.awemeId || '-'}`,
            `modal_id=${asset.modalId || '-'}`,
            `title=${asset.title || '-'}`,
            `author=${asset.author || '-'}`,
            `best=${asset.bestUrl || '-'}`,
            '',
            '# all urls',
            ...asset.urls,
          ].join('\n');

          await copyText(text);
          showToast(
            `已复制 ${asset.urls.length} 条链接到剪贴板\n` +
            `来源: store=${asset.sourceStats.store}, dom=${asset.sourceStats.dom}, perf=${asset.sourceStats.perf}`,
            3000
          );

          if (asset.bestUrl) {
            const idForName = asset.awemeId || asset.modalId || 'douyin';
            const file = sanitizeFilename(idForName + '-' + (asset.title || 'video')) + '.mp4';
            try {
              await downloadViaPageRequest(asset.bestUrl, file);
              showToast('已通过脚本内请求下载（带页面上下文）', 1800);
            } catch (e) {
              console.warn('[VOD 下载回退] 页面内请求失败，改为直链下载', e);
              triggerDownload(asset.bestUrl, file);
              showToast('脚本内下载失败，已回退为直链下载', 2200);
            }
          }

          btn.textContent = `已提取 ${asset.urls.length}`;
          setTimeout(() => {
            btn.textContent = '提取视频';
          }, 1800);
          setBusy('');
        } catch (e) {
          console.error('[VOD 提取] 失败', e);
          showToast('提取失败: ' + (e && e.message ? e.message : e), 3200);
          setBusy('');
        }
      });

      btn.title = '点击：复制全部视频链接并尝试下载最佳链接';
      document.body.appendChild(btn);
    }

    if (!document.getElementById(BTN_JUMP_ID)) {
      const jumpBtn = document.createElement('button');
      jumpBtn.id = BTN_JUMP_ID;
      jumpBtn.textContent = '转视频页';
      Object.assign(jumpBtn.style, {
        position: 'fixed',
        right: '24px',
        bottom: '165px',
        zIndex: 2147483647,
        padding: '8px 14px',
        borderRadius: '999px',
        border: '1px solid rgba(255,255,255,.35)',
        background: 'rgba(0,0,0,.55)',
        color: '#fff',
        fontSize: '13px',
        fontWeight: '600',
        cursor: 'pointer',
        boxShadow: '0 6px 16px rgba(0,0,0,.22)',
        userSelect: 'none',
      });

      jumpBtn.addEventListener('click', () => {
        const canonical = getCanonicalVideoUrl();
        if (!canonical) {
          showToast('未识别到视频 ID，无法跳转到 video 级链接。', 2400);
          return;
        }
        const current = location.href;
        if (current.startsWith(canonical) && !/[?&]modal_id=/.test(current)) {
          showToast('当前已经是 video 级链接。', 1800);
          return;
        }
        showToast('正在跳转到 video 级链接…', 1200);
        location.href = canonical;
      });

      jumpBtn.title = '把弹窗链接规范化为 /video/{id}';
      document.body.appendChild(jumpBtn);
    }
  }

  /* ============================================================
   * 6) 启动
   * ============================================================ */
  patchFetch();
  patchXHR();
  createButton();

  // SPA 场景：确保按钮常驻
  const obs = new MutationObserver(() => createButton());
  obs.observe(document.documentElement, { childList: true, subtree: true });
})();
