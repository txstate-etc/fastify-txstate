import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { access, constants, mkdir, rename, unlink, stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { rescue, randomid } from 'txstate-utils'

export interface FileHandler {
  init: () => Promise<void>
  put: (stream: Readable) => Promise<{ checksum: string, size: number }> // returns a checksum
  get: (checksum: string) => Readable
  remove: (checksum: string) => Promise<void>
}

export class FileSystemHandler implements FileHandler {
  options: { tmpdir: string, permdir: string }

  constructor (options: { tmpdir?: string, permdir?: string } = {}) {
    this.options = {
      tmpdir: options.tmpdir ?? '/files/tmp/',
      permdir: options.permdir ?? '/files/storage/'
    }
    if (!this.options.tmpdir.endsWith('/')) this.options.tmpdir += '/'
    if (!this.options.permdir.endsWith('/')) this.options.permdir += '/'
  }

  #getTmpLocation () {
    return `${this.options.tmpdir}${randomid(12)}`
  }

  #getFileLocation (checksum: string) {
    return `${this.options.permdir}${checksum.slice(0, 1)}/${checksum.slice(1, 2)}/${checksum.slice(2)}`
  }

  async #moveToPerm (tmp: string, checksum: string) {
    const checksumpath = this.#getFileLocation(checksum)
    await mkdir(dirname(checksumpath), { recursive: true })
    await rename(tmp, checksumpath)
  }

  async init () {
    await mkdir(this.options.tmpdir, { recursive: true })
    await mkdir(this.options.permdir, { recursive: true })
  }

  get (checksum: string) {
    const filepath = this.#getFileLocation(checksum)
    const stream = createReadStream(filepath)
    return stream
  }

  async exists (checksum: string) {
    const filepath = this.#getFileLocation(checksum)
    return (await rescue(access(filepath, constants.R_OK), false)) !== false
  }

  async fileSize (checksum: string) {
    const filepath = this.#getFileLocation(checksum)
    const info = await stat(filepath)
    return info.size
  }

  async put (stream: Readable) {
    const tmp = this.#getTmpLocation()
    const hash = createHash('sha256')
    let size = 0
    stream.on('data', (data: Buffer) => { hash.update(data); size += data.length })
    try {
      const out = createWriteStream(tmp)
      const flushedPromise = new Promise((resolve, reject) => {
        out.on('close', resolve as () => void)
        out.on('error', reject)
      })
      await pipeline(stream, out)
      await flushedPromise
      const checksum = hash.digest('base64url')
      const rereadhash = createHash('sha256')
      const read = createReadStream(tmp)
      for await (const chunk of read) {
        rereadhash.update(chunk as Buffer)
      }
      const rereadsum = rereadhash.digest('base64url')
      if (rereadsum !== checksum) throw new Error('File did not write to disk correctly. Please try uploading again.')
      await this.#moveToPerm(tmp, checksum)
      return { checksum, size }
    } catch (e: any) {
      await rescue(unlink(tmp))
      throw e
    }
  }

  async remove (checksum: string) {
    const filepath = this.#getFileLocation(checksum)
    try {
      await unlink(filepath)
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException
      if (err.code === 'ENOENT') return // file already gone, nothing to do
      throw e
    }
  }
}

export const fileHandler = new FileSystemHandler()
