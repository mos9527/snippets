// ==UserScript==
// @name         抖音收藏表情提取器 (Douyin Emoticon Extractor)
// @namespace    https://github.com/local/douyin-emoticon-extractor
// @version      1.0.0
// @description  在抖音页面提取"我的收藏"自定义表情，打包成 store 模式（无压缩）ZIP 并下载。纯原生 JS，无第三方依赖。
// @author       you
// @match        https://www.douyin.com/*
// @match        https://*.douyin.com/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  /* ============================================================
   * 1. 原生 store-mode ZIP 打包器（method=0，无压缩，平坦结构）
   * ============================================================ */

  // CRC32 查表
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(bytes) {
    let crc = 0 ^ -1;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ bytes[i]) & 0xff];
    }
    return (crc ^ -1) >>> 0;
  }

  // 把若干 {name, data:Uint8Array} 打包成 store-mode ZIP 的 Blob
  function buildStoreZip(files) {
    const enc = new TextEncoder();
    const localParts = [];
    const central = [];
    let offset = 0;

    // 固定的 DOS 时间/日期（无需真实时间，兼容即可）
    const dosTime = 0;
    const dosDate = 0x21; // 1980-01-01

    for (const f of files) {
      const nameBytes = enc.encode(f.name);
      const data = f.data;
      const crc = crc32(data);
      const size = data.length;

      // ---- Local file header (30 字节 + 文件名) ----
      const lh = new Uint8Array(30 + nameBytes.length);
      const lv = new DataView(lh.buffer);
      lv.setUint32(0, 0x04034b50, true);   // signature
      lv.setUint16(4, 20, true);           // version needed
      lv.setUint16(6, 0x0800, true);       // flags: UTF-8 文件名
      lv.setUint16(8, 0, true);            // method = 0 (store)
      lv.setUint16(10, dosTime, true);
      lv.setUint16(12, dosDate, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, size, true);        // compressed size = size
      lv.setUint32(22, size, true);        // uncompressed size
      lv.setUint16(26, nameBytes.length, true);
      lv.setUint16(28, 0, true);           // extra len
      lh.set(nameBytes, 30);

      localParts.push(lh, data);

      // ---- Central directory header (46 字节 + 文件名) ----
      const ch = new Uint8Array(46 + nameBytes.length);
      const cv = new DataView(ch.buffer);
      cv.setUint32(0, 0x02014b50, true);   // signature
      cv.setUint16(4, 20, true);           // version made by
      cv.setUint16(6, 20, true);           // version needed
      cv.setUint16(8, 0x0800, true);       // flags: UTF-8
      cv.setUint16(10, 0, true);           // method = store
      cv.setUint16(12, dosTime, true);
      cv.setUint16(14, dosDate, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, size, true);
      cv.setUint32(24, size, true);
      cv.setUint16(28, nameBytes.length, true);
      cv.setUint16(30, 0, true);           // extra len
      cv.setUint16(32, 0, true);           // comment len
      cv.setUint16(34, 0, true);           // disk number
      cv.setUint16(36, 0, true);           // internal attrs
      cv.setUint32(38, 0, true);           // external attrs
      cv.setUint32(42, offset, true);      // local header offset
      ch.set(nameBytes, 46);
      central.push(ch);

      offset += lh.length + data.length;
    }

    // 中央目录总大小
    const centralSize = central.reduce((s, c) => s + c.length, 0);
    const centralOffset = offset;

    // ---- End of central directory (22 字节) ----
    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(4, 0, true);
    ev.setUint16(6, 0, true);
    ev.setUint16(8, files.length, true);
    ev.setUint16(10, files.length, true);
    ev.setUint32(12, centralSize, true);
    ev.setUint32(16, centralOffset, true);
    ev.setUint16(20, 0, true);

    return new Blob([...localParts, ...central, eocd], {
      type: 'application/zip',
    });
  }

  /* ============================================================
   * 2. 收集收藏表情 & 抓取字节
   * ============================================================ */

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // 找到自定义/收藏表情容器
  function findCustomContainer() {
    return document.querySelector('[class*="CustomEmoji"]');
  }

  // 找到容器对应的可滚动祖先
  function findScroller(el) {
    let p = el;
    for (let i = 0; i < 8 && p; i++) {
      p = p.parentElement;
      if (!p) break;
      const s = getComputedStyle(p);
      if (/(auto|scroll)/.test(s.overflowY) && p.scrollHeight > p.clientHeight) {
        return p;
      }
    }
    return null;
  }

  // 滚动加载，返回去重后的全部图片 URL
  async function collectEmoticonUrls(onProgress) {
    const container = findCustomContainer();
    if (!container) return [];
    const scroller = findScroller(container);

    const urls = new Set();
    const grab = () => {
      container.querySelectorAll('img').forEach((img) => {
        if (img.src && /^https?:/.test(img.src)) urls.add(img.src);
      });
    };

    grab();
    if (scroller) {
      let stable = 0;
      let last = -1;
      for (let i = 0; i < 60 && stable < 4; i++) {
        scroller.scrollTop = scroller.scrollHeight;
        await sleep(220);
        grab();
        if (urls.size === last) stable++;
        else stable = 0;
        last = urls.size;
        if (onProgress) onProgress(`加载中… 已发现 ${urls.size} 个表情`);
      }
      scroller.scrollTop = 0;
    }
    return Array.from(urls);
  }

  // 从 URL 推断文件扩展名（保留 .webp / .awebp / .gif / .png 等，保留动图）
  function extFromUrl(url) {
    const path = url.split('?')[0];
    const m = path.match(/\.([a-z0-9]{2,5})$/i);
    if (m) return m[1].toLowerCase();
    return 'webp';
  }

  // 从 URL 提取稳定的短 id，用于平坦文件名
  function idFromUrl(url) {
    const path = url.split('?')[0];
    const segs = path.split('/');
    let last = segs[segs.length - 1] || 'emoticon';
    last = last.split('~')[0];            // 去掉 ~tplv... 模板后缀
    last = last.replace(/\.[a-z0-9]+$/i, ''); // 去掉扩展名
    last = last.replace(/[^a-zA-Z0-9_-]/g, '');
    return last.slice(0, 48) || 'emoticon';
  }

  async function fetchAll(urls, onProgress) {
    const files = [];
    const used = new Set();
    let done = 0;
    // 限制并发，避免被限流
    const CONCURRENCY = 6;
    let cursor = 0;

    async function worker() {
      while (cursor < urls.length) {
        const idx = cursor++;
        const url = urls[idx];
        try {
          const r = await fetch(url, { mode: 'cors', credentials: 'omit' });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          const buf = new Uint8Array(await r.arrayBuffer());
          const ext = extFromUrl(url);
          let base = String(idx + 1).padStart(3, '0') + '_' + idFromUrl(url);
          let name = base + '.' + ext;
          let n = 1;
          while (used.has(name)) name = base + '_' + n++ + '.' + ext;
          used.add(name);
          files.push({ name, data: buf });
        } catch (e) {
          console.warn('[表情提取] 跳过', url, e);
        } finally {
          done++;
          if (onProgress) onProgress(`下载中… ${done}/${urls.length}`);
        }
      }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return files;
  }

  function downloadBlob(blob, filename) {
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  /* ============================================================
   * 3. 悬浮按钮 UI
   * ============================================================ */

  function createButton() {
    if (document.getElementById('dy-emoticon-extractor-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'dy-emoticon-extractor-btn';
    btn.textContent = '提取表情';
    Object.assign(btn.style, {
      position: 'fixed',
      right: '24px',
      bottom: '120px',
      zIndex: 2147483647,
      padding: '10px 16px',
      borderRadius: '999px',
      border: 'none',
      background: 'linear-gradient(135deg,#fe2c55,#ff6b81)',
      color: '#fff',
      fontSize: '14px',
      fontWeight: '600',
      cursor: 'pointer',
      boxShadow: '0 6px 18px rgba(254,44,85,.45)',
      userSelect: 'none',
      transition: 'transform .15s ease, opacity .2s ease',
    });
    btn.onmouseenter = () => (btn.style.transform = 'scale(1.06)');
    btn.onmouseleave = () => (btn.style.transform = 'scale(1)');

    const setBusy = (text) => {
      btn.disabled = !!text;
      btn.style.opacity = text ? '0.85' : '1';
      btn.style.cursor = text ? 'default' : 'pointer';
      btn.textContent = text || '提取表情';
    };

    btn.addEventListener('click', async () => {
      if (btn.disabled) return;
      try {
        if (!findCustomContainer()) {
          alert('未找到收藏表情面板。\n请先在抖音里打开评论/私信，点开表情(emoji)面板并切到"我的收藏"，再点此按钮。');
          return;
        }
        setBusy('收集表情…');
        const urls = await collectEmoticonUrls(setBusy);
        if (!urls.length) {
          alert('没有收集到表情图片。');
          setBusy('');
          return;
        }
        setBusy(`下载 0/${urls.length}`);
        const files = await fetchAll(urls, setBusy);
        if (!files.length) {
          alert('下载失败，未获得任何图片。');
          setBusy('');
          return;
        }
        setBusy('打包 ZIP…');
        const blob = buildStoreZip(files);
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        downloadBlob(blob, `douyin-emoticons-${files.length}-${ts}.zip`);
        setBusy('');
        btn.textContent = `已导出 ${files.length} 个`;
        setTimeout(() => (btn.textContent = '提取表情'), 2500);
      } catch (e) {
        console.error('[表情提取] 失败', e);
        alert('提取失败：' + (e && e.message ? e.message : e));
        setBusy('');
      }
    });

    document.body.appendChild(btn);
  }

  // 页面可能是 SPA，反复确保按钮存在
  createButton();
  const obs = new MutationObserver(() => createButton());
  obs.observe(document.documentElement, { childList: true, subtree: true });
})();
