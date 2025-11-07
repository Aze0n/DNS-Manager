import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'

// https nur dev falls certs vorhanden
function devHttps() {
  try {
    const keyPath = path.resolve(__dirname, '../certs/key.pem')
    const certPath = path.resolve(__dirname, '../certs/cert.pem')
    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      return {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
      }
    }
  } catch (_) {
    // ignorieren
  }
  return undefined
}

export default defineConfig({
  server: {
    https: devHttps(),
    proxy: {
      '/api': {
        target: 'https://127.0.0.1:8000',
        changeOrigin: true,
        secure: false, // self-signed ok
      },
    },
  },
})

