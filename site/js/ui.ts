import { hex, printable } from '@core/bytes'
import { bytesToBase64 } from '@core/encode'
import type { ParseResult, Region } from '@core/region'

// ---------------------------------------------------------------- dom utils

export const $ = <T extends HTMLElement = HTMLElement>(sel: string, root: ParentNode = document): T => {
  const node = root.querySelector(sel)
  if (!node) throw new Error(`missing element: ${sel}`)
  return node as T
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text) node.textContent = text
  return node
}

export function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number): (...args: A) => void {
  let t: ReturnType<typeof setTimeout> | undefined
  return (...args: A) => {
    clearTimeout(t)
    t = setTimeout(() => fn(...args), ms)
  }
}

// ---------------------------------------------------------------- chrome (header/theme/toast)

export function initChrome(): void {
  const path = location.pathname
  document.querySelectorAll<HTMLAnchorElement>('.site-nav a').forEach((a) => {
    if (path.startsWith(a.pathname) && a.pathname !== '/') a.setAttribute('aria-current', 'page')
  })
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'
    if (next === 'light') document.documentElement.dataset.theme = 'light'
    else delete document.documentElement.dataset.theme
    try {
      localStorage.setItem('hexbase-theme', next)
    } catch {
      /* private mode */
    }
  })
  // click-to-copy for anything marked .copyable
  document.addEventListener('click', (e) => {
    const target = (e.target as HTMLElement).closest<HTMLElement>('.copyable')
    if (target) void copyText(target.dataset.copy ?? target.textContent ?? '')
  })
}

let toastTimer: ReturnType<typeof setTimeout> | undefined

export function toast(message: string): void {
  const node = document.getElementById('toast')
  if (!node) return
  node.textContent = message
  node.classList.add('show')
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => node.classList.remove('show'), 2200)
}

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    toast('Copied to clipboard')
  } catch {
    toast('Copy failed — clipboard unavailable')
  }
}

/** Wire up a .tabs strip: buttons carry data-tab, panels carry data-panel. */
export function initTabs(scope: HTMLElement, onChange?: (id: string) => void): void {
  const buttons = [...scope.querySelectorAll<HTMLButtonElement>('.tabs button[data-tab]')]
  const activate = (id: string) => {
    buttons.forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === id)))
    scope.querySelectorAll<HTMLElement>('[data-panel]').forEach((p) => {
      p.classList.toggle('active', p.dataset.panel === id)
    })
    onChange?.(id)
  }
  buttons.forEach((b) => b.addEventListener('click', () => activate(b.dataset.tab!)))
  if (buttons[0]) activate(buttons[0].dataset.tab!)
}

export function showMsg(node: HTMLElement, kind: 'ok' | 'err' | 'warn', text: string): void {
  node.className = `msg ${kind}`
  node.textContent = text
}

export function hideMsg(node: HTMLElement): void {
  node.className = 'msg hidden'
  node.textContent = ''
}

// ---------------------------------------------------------------- hex view

const PAGE_SIZE = 4096

export class HexView {
  private data: Uint8Array = new Uint8Array(0)
  private windowStart = 0
  private hl: [number, number] | null = null
  private view: HTMLElement
  private bar: HTMLElement
  private info: HTMLElement
  private label: HTMLElement
  private spans: { b: HTMLElement; a: HTMLElement }[] = []
  onByteClick: ((index: number) => void) | null = null

  constructor(container: HTMLElement) {
    this.bar = el('div', 'hexbar')
    const prev = el('button', 'btn small', '◀')
    const next = el('button', 'btn small', '▶')
    this.label = el('span', '', '')
    const jump = el('input') as HTMLInputElement
    jump.placeholder = 'go to 0x…'
    jump.title = 'Jump to offset (hex like 0x1F0 or decimal)'
    this.info = el('span', '', '')
    const spacer = el('span', 'spacer')
    this.bar.append(prev, this.label, next, jump, spacer, this.info)

    const wrap = el('div', 'hexwrap')
    this.view = el('div', 'hexview')
    wrap.append(this.view)
    container.append(this.bar, wrap)

    prev.addEventListener('click', () => this.setWindow(this.windowStart - PAGE_SIZE))
    next.addEventListener('click', () => this.setWindow(this.windowStart + PAGE_SIZE))
    jump.addEventListener('change', () => {
      const raw = jump.value.trim()
      const value = /^0x/i.test(raw) ? parseInt(raw, 16) : /^[0-9a-fA-F]+$/.test(raw) && /[a-fA-F]/.test(raw) ? parseInt(raw, 16) : parseInt(raw, 10)
      if (Number.isFinite(value)) this.setWindow(value - (value % PAGE_SIZE))
    })
    this.view.addEventListener('mouseover', (e) => {
      const t = e.target as HTMLElement
      if (t.dataset.i) {
        const i = Number(t.dataset.i)
        const byte = this.data[i]
        this.info.textContent = `0x${hex(i, 6)} (${i})  =  0x${hex(byte)}  ${byte}  0b${byte.toString(2).padStart(8, '0')}  '${printable(byte)}'`
      }
    })
    this.view.addEventListener('click', (e) => {
      const t = e.target as HTMLElement
      if (t.dataset.i && this.onByteClick) this.onByteClick(Number(t.dataset.i))
    })
  }

  setData(data: Uint8Array): void {
    this.data = data
    this.hl = null
    this.setWindow(0, true)
  }

  private setWindow(start: number, force = false): void {
    const max = Math.max(0, Math.floor((this.data.length - 1) / PAGE_SIZE) * PAGE_SIZE)
    const clamped = Math.min(Math.max(0, start), max)
    if (!force && clamped === this.windowStart) return
    this.windowStart = clamped
    this.render()
  }

  highlight(offset: number, length: number): void {
    // jump the window so the region start is visible
    if (offset < this.windowStart || offset >= this.windowStart + PAGE_SIZE) {
      this.windowStart = Math.floor(offset / PAGE_SIZE) * PAGE_SIZE
      this.hl = [offset, length]
      this.render()
      return
    }
    this.applyHl(false)
    this.hl = [offset, length]
    this.applyHl(true)
  }

  private applyHl(on: boolean): void {
    if (!this.hl) return
    const [off, len] = this.hl
    const from = Math.max(off, this.windowStart)
    const to = Math.min(off + len, this.windowStart + PAGE_SIZE, this.data.length)
    for (let i = from; i < to; i++) {
      const cell = this.spans[i - this.windowStart]
      if (!cell) continue
      cell.b.classList.toggle('hl', on)
      cell.a.classList.toggle('hl', on)
    }
  }

  private render(): void {
    const { data, windowStart } = this
    const end = Math.min(windowStart + PAGE_SIZE, data.length)
    this.view.textContent = ''
    this.spans = []
    const frag = document.createDocumentFragment()

    if (data.length === 0) {
      this.view.textContent = '(no data)'
      this.label.textContent = ''
      return
    }

    for (let row = windowStart; row < end; row += 16) {
      const line = el('div', 'hexrow')
      const off = el('span', 'off', hex(row, 8) + '  ')
      line.append(off)
      const asciiSpans: HTMLElement[] = []
      for (let i = row; i < row + 16; i++) {
        if (i < end) {
          const b = el('span', 'b', hex(data[i]))
          b.dataset.i = String(i)
          line.append(b, document.createTextNode(i === row + 7 ? '  ' : ' '))
          const a = el('span', 'a', printable(data[i]))
          a.dataset.i = String(i)
          asciiSpans.push(a)
          this.spans[i - windowStart] = { b, a }
        } else {
          line.append(document.createTextNode(i === row + 7 ? '    ' : '   '))
        }
      }
      line.append(document.createTextNode(' '))
      for (const a of asciiSpans) line.append(a)
      frag.append(line)
    }
    this.view.append(frag)
    const pages = Math.ceil(data.length / PAGE_SIZE)
    this.label.textContent =
      pages > 1
        ? `0x${hex(windowStart, 6)}–0x${hex(end - 1, 6)} · page ${windowStart / PAGE_SIZE + 1}/${pages}`
        : `${data.length} bytes`
    this.bar.querySelectorAll('button').forEach((b, idx) => {
      ;(b as HTMLButtonElement).disabled = idx === 0 ? windowStart === 0 : end >= data.length
    })
    this.applyHl(true)
  }
}

// ---------------------------------------------------------------- region tree

export class RegionTree {
  private container: HTMLElement
  private note: HTMLElement
  private selected: HTMLElement | null = null
  onSelect: ((region: Region) => void) | null = null

  constructor(container: HTMLElement, note: HTMLElement) {
    this.container = container
    this.note = note
  }

  set(regions: Region[]): void {
    this.container.textContent = ''
    this.selected = null
    this.note.textContent = 'Select a field to see what it means.'
    const frag = document.createDocumentFragment()
    for (const r of regions) frag.append(this.renderNode(r, 0))
    this.container.append(frag)
  }

  private renderNode(region: Region, depth: number): HTMLElement {
    const node = el('div', 'tnode')
    const row = el('div', 'trow')
    const tw = el('span', 'tw')
    const hasKids = !!region.children?.length
    tw.textContent = hasKids ? '▾' : '·'
    row.append(tw)
    row.append(el('span', 'tname', region.name))
    if (region.value) row.append(el('span', 'tval', region.value))
    if (region.flag) {
      const badge = el('span', `badge ${region.flag}`, region.flag === 'ok' ? '✓' : region.flag === 'warn' ? '!' : '✗')
      row.append(badge)
    }
    row.append(el('span', 'toff', `0x${hex(region.offset, 4)}+${region.length}`))
    node.append(row)

    if (hasKids) {
      const kids = el('div', 'tkids')
      for (const child of region.children!) kids.append(this.renderNode(child, depth + 1))
      node.append(kids)
      if (depth >= 1) node.classList.add('collapsed'), (tw.textContent = '▸')
      tw.addEventListener('click', (e) => {
        e.stopPropagation()
        const collapsed = node.classList.toggle('collapsed')
        tw.textContent = collapsed ? '▸' : '▾'
      })
    }

    row.addEventListener('click', () => {
      this.selected?.classList.remove('sel')
      row.classList.add('sel')
      this.selected = row
      this.note.innerHTML = ''
      const head = el('b', '', `${region.name}`)
      const span = el('span', '', `  ·  offset 0x${hex(region.offset, 4)} (${region.offset}), ${region.length} byte${region.length === 1 ? '' : 's'}`)
      this.note.append(head, span)
      if (region.value) this.note.append(el('div', '', `value: ${region.value}`))
      if (region.note) this.note.append(el('div', 'dim', region.note))
      this.onSelect?.(region)
    })
    return node
  }
}

/** Render summary lines + warnings of a ParseResult into a container. */
export function renderResultHead(container: HTMLElement, result: ParseResult): void {
  container.textContent = ''
  const title = el('div', '', '')
  title.style.cssText = 'font-family:var(--font-mono);font-weight:700;color:var(--text-strong);margin-bottom:6px'
  title.textContent = result.format
  container.append(title)
  for (const line of result.summary) container.append(el('div', 'sumline', line))
  for (const w of result.warnings) {
    const m = el('div', 'msg warn', `⚠ ${w}`)
    container.append(m)
  }
}

// ---------------------------------------------------------------- share client

export async function createShare(tool: string, bytes: Uint8Array, filename?: string): Promise<string> {
  const res = await fetch('/api/share', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tool, content: bytesToBase64(bytes), filename }),
  })
  const data = (await res.json().catch(() => ({}))) as { url?: string; error?: string }
  if (!res.ok || !data.url) throw new Error(data.error ?? `share failed (${res.status})`)
  return data.url
}

export async function loadShare(code: string): Promise<{ bytes: Uint8Array; filename: string | null }> {
  const res = await fetch(`/api/share/${encodeURIComponent(code)}`)
  if (!res.ok) throw new Error('this share link has expired or does not exist')
  const bytes = new Uint8Array(await res.arrayBuffer())
  return { bytes, filename: res.headers.get('x-hexbase-filename') || null }
}

export function shareParam(): string | null {
  return new URLSearchParams(location.search).get('share')
}

/** Wire a Share button: gets content bytes, posts them, copies the short URL. */
export function bindShare(button: HTMLElement, tool: string, getPayload: () => { bytes: Uint8Array; filename?: string } | null): void {
  button.addEventListener('click', () => {
    void (async () => {
      const payload = getPayload()
      if (!payload || payload.bytes.length === 0) {
        toast('Nothing to share yet')
        return
      }
      if (payload.bytes.length > 256 * 1024) {
        toast('Too large to share (limit 256 KB)')
        return
      }
      button.setAttribute('disabled', '')
      try {
        const url = await createShare(tool, payload.bytes, payload.filename)
        await navigator.clipboard.writeText(url).catch(() => undefined)
        toast(`Share link copied — ${url}`)
      } catch (e) {
        toast(e instanceof Error ? e.message : 'share failed')
      } finally {
        button.removeAttribute('disabled')
      }
    })()
  })
}
