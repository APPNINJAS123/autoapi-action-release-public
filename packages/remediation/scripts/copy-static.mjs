import { cp, mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

await mkdir(resolve('dist/python'), { recursive: true })
await cp(resolve('src/python/analyze.py'), resolve('dist/python/analyze.py'))
await cp(resolve('src/python/firecrawl_rewrite.py'), resolve('dist/python/firecrawl_rewrite.py'))
await mkdir(resolve('dist/go'), { recursive: true })
await cp(resolve('src/go/package_usage.go'), resolve('dist/go/package_usage.go'))
await cp(resolve('src/openrouter-fetch.mjs'), resolve('dist/openrouter-fetch.mjs'))
await cp(resolve('src/openrouter-preload.mjs'), resolve('dist/openrouter-preload.mjs'))
