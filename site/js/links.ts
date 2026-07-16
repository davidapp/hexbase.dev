import { $, el, initChrome, showMsg } from './ui'

initChrome()

interface LinksPayload {
  categories: { category: string; links: { title: string; url: string; description: string }[] }[]
}

const grid = $('#links')
const msg = $('#links-msg')
const filter = $<HTMLInputElement>('#filter')

function render(data: LinksPayload): void {
  grid.textContent = ''
  for (const cat of data.categories) {
    const box = el('div', 'link-cat card')
    box.append(el('h2', '', cat.category))
    for (const link of cat.links) {
      const a = el('a', 'link-item') as HTMLAnchorElement
      a.href = link.url
      a.target = '_blank'
      a.rel = 'noopener'
      a.dataset.search = `${cat.category} ${link.title} ${link.description} ${link.url}`.toLowerCase()
      a.append(el('div', 'lt', link.title))
      a.append(el('div', 'ld', link.description))
      a.append(el('div', 'lu', link.url.replace(/^https?:\/\//, '')))
      box.append(a)
    }
    grid.append(box)
  }
}

function applyFilter(): void {
  const q = filter.value.trim().toLowerCase()
  grid.querySelectorAll<HTMLElement>('.link-item').forEach((item) => {
    item.style.display = !q || item.dataset.search!.includes(q) ? '' : 'none'
  })
  grid.querySelectorAll<HTMLElement>('.link-cat').forEach((cat) => {
    const visible = [...cat.querySelectorAll<HTMLElement>('.link-item')].some((i) => i.style.display !== 'none')
    cat.style.display = visible ? '' : 'none'
  })
}

filter.addEventListener('input', applyFilter)

fetch('/api/links')
  .then((r) => {
    if (!r.ok) throw new Error(`API returned ${r.status}`)
    return r.json() as Promise<LinksPayload>
  })
  .then(render)
  .catch(() => {
    showMsg(msg, 'err', 'Could not load the links directory (is the D1 database seeded? run: npm run db:local). ')
  })
