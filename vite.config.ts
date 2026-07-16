import { defineConfig, type Plugin } from 'vite'
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(new URL(import.meta.url)))
const site = resolve(root, 'site')

/** Inlines site/partials/<name>.html wherever a page contains <!--#include:name--> */
function partials(): Plugin {
  return {
    name: 'hexbase-partials',
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        return html.replace(/<!--#include:([\w-]+)-->/g, (_m, name: string) =>
          readFileSync(resolve(site, 'partials', `${name}.html`), 'utf8'),
        )
      },
    },
  }
}

export default defineConfig({
  root: site,
  publicDir: resolve(root, 'public'),
  plugins: [partials()],
  resolve: {
    alias: { '@core': resolve(root, 'src/core') },
  },
  build: {
    outDir: resolve(root, 'dist'),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        home: resolve(site, 'index.html'),
        notfound: resolve(site, '404.html'),
        links: resolve(site, 'links/index.html'),
        hex: resolve(site, 'tools/hex/index.html'),
        json: resolve(site, 'tools/json/index.html'),
        xml: resolve(site, 'tools/xml/index.html'),
        timestamp: resolve(site, 'tools/timestamp/index.html'),
        encode: resolve(site, 'tools/encode/index.html'),
        packet: resolve(site, 'tools/packet/index.html'),
      },
    },
  },
})
