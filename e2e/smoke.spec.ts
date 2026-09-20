import { expect, test, type Page } from '@playwright/test'

/** Fail a test on any uncaught page error or console error. */
function watchConsole(page: Page): () => void {
  const problems: string[] = []
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push(`console: ${m.text()}`)
  })
  return () => expect(problems, 'no console/page errors').toEqual([])
}

const PAGES = ['/', '/tools/hex/', '/tools/packet/', '/tools/json/', '/tools/diff/', '/tools/xml/', '/tools/timestamp/', '/tools/encode/', '/tools/cert/', '/tools/random/', '/formats/', '/formats/png/', '/terms/', '/privacy/']

test('every page loads without console errors', async ({ page }) => {
  const check = watchConsole(page)
  for (const path of PAGES) {
    await page.goto(path)
    await expect(page).toHaveTitle(/hexbase\.dev/)
    await expect(page.locator('footer a[href="https://github.com/darvlab/hexbase.dev"]').first()).toBeVisible()
  }
  check()
})

test('hex inspector: demo deep link parses a PNG and links its guide', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/hex/?demo=png')
  await expect(page.locator('#summary')).toContainText('PNG image')
  await expect(page.locator('#summary .guide-link')).toHaveAttribute('href', '/formats/png/')
  await expect(page.locator('#tree .trow').first()).toContainText('PNG signature')
  check()
})

test('hex inspector: structure tree is keyboard navigable', async ({ page }) => {
  await page.goto('/tools/hex/?demo=png')
  const rows = page.locator('#tree .trow')
  await expect(rows.first()).toHaveAttribute('role', 'treeitem')
  await rows.first().focus()
  await page.keyboard.press('ArrowDown')
  await expect(rows.nth(1)).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(rows.nth(1)).toHaveClass(/sel/)
  await expect(page.locator('#hexview .b.hl').first()).toBeVisible()
})

test('packet decoder: sample decodes through DNS', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/packet/')
  await page.locator('#samples button').first().click()
  await expect(page.locator('#summary')).toContainText('DNS query')
  check()
})

test('json toolkit: sample formats', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/json/')
  await page.locator('#sample').click()
  await page.locator('#format').click()
  await expect(page.locator('#output')).toContainText('{')
  check()
})

test('json diff: sample reports differences with paths', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/diff/')
  await page.locator('#sample').click()
  await expect(page.locator('#diff-out .drow').first()).toBeVisible()
  await expect(page.locator('#diff-stats')).toContainText('differences')
  check()
})

test('certificate decoder: sample chain parses and links', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/cert/')
  await page.locator('#sample').click()
  await expect(page.locator('#summary')).toContainText('example.com')
  await expect(page.locator('#fingerprints tr')).toHaveCount(2)
  await expect(page.locator('#chain .chainrow').first()).toContainText('leaf')
  check()
})

test('timestamp converter: ?t= deep link converts', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/timestamp/?t=1700000000')
  await expect(page.locator('#interp tr').first()).toBeVisible()
  await expect(page.locator('#interp')).toContainText('2023')
  check()
})

test('encode/decode: base64 round trip', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/encode/')
  await page.locator('#b64-in').fill('hexbase')
  await page.locator('#b64-enc').click()
  await expect(page.locator('#b64-out')).toContainText('aGV4YmFzZQ==')
  check()
})

test('xml toolkit: sample formats', async ({ page }) => {
  const check = watchConsole(page)
  await page.goto('/tools/xml/')
  await page.locator('#sample').click()
  await page.locator('#format').click()
  await expect(page.locator('#output')).toContainText('<')
  check()
})
