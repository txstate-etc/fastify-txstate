import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { access, constants, mkdir, opendir, readdir, rename, unlink, stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { rescue, randomid } from 'txstate-utils'

function isENOENT (e: unknown) {
  return (e as NodeJS.ErrnoException).code === 'ENOENT'
}

async function fileExists (filepath: string) {
  return (await rescue(access(filepath, constants.R_OK), false)) !== false
}

export interface FileRange {
  start: number
  end?: number
}

export interface FileHandler {
  init: () => Promise<void>
  put: (stream: Readable) => Promise<{ checksum: string, size: number }> // returns a checksum
  /**
   * Byte offsets in range are inclusive and zero-based, like fs.createReadStream, so { start: 0, end: 9 } is
   * the first 10 bytes. Leave out end to read to the end of the file. Callers are expected to clamp the range
   * to the file's size first, since backends disagree on what to do with an out-of-bounds range.
   */
  get: (checksum: string, range?: FileRange) => Readable
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
    // 43 chars is a base64url sha256
    if (checksum.length === 43) checksum = Buffer.from(checksum, 'base64url').toString('hex')
    return `${this.options.permdir}${checksum.slice(0, 1)}/${checksum.slice(1, 2)}/${checksum.slice(2)}`
  }

  #getLegacyFileLocation (checksum: string) {
    if (checksum.length === 64) checksum = Buffer.from(checksum, 'hex').toString('base64url')
    return `${this.options.permdir}${checksum.slice(0, 1)}/${checksum.slice(1, 2)}/${checksum.slice(2)}`
  }

  async #hashFile (filepath: string) {
    const hash = createHash('sha256')
    for await (const chunk of createReadStream(filepath)) hash.update(chunk as Buffer)
    return hash.digest('base64url')
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

  async* #read (checksum: string, range?: FileRange) {
    try {
      yield* createReadStream(this.#getFileLocation(checksum), range)
    } catch (e: unknown) {
      if (!isENOENT(e)) throw e
      yield* createReadStream(this.#getLegacyFileLocation(checksum), range)
    }
  }

  // get, exists, fileSize, and remove fall back to the legacy location for files that haven't been migrated
  get (checksum: string, range?: FileRange) {
    return Readable.from(this.#read(checksum, range), { objectMode: false })
  }

  async exists (checksum: string) {
    return await fileExists(this.#getFileLocation(checksum)) || await fileExists(this.#getLegacyFileLocation(checksum))
  }

  async fileSize (checksum: string) {
    try {
      return (await stat(this.#getFileLocation(checksum))).size
    } catch (e: unknown) {
      if (!isENOENT(e)) throw e
      return (await stat(this.#getLegacyFileLocation(checksum))).size
    }
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
      const rereadsum = await this.#hashFile(tmp)
      if (rereadsum !== checksum) throw new Error('File did not write to disk correctly. Please try uploading again.')
      await this.#moveToPerm(tmp, checksum)
      return { checksum, size }
    } catch (e: any) {
      await rescue(unlink(tmp))
      throw e
    }
  }

  /**
   * Moves a file stored under its base64url checksum (as older versions did) to its hex location.
   * Accepts either form of checksum. Returns false if there was no legacy file to move.
   */
  async migrateLegacyFile (checksum: string) {
    const legacypath = this.#getLegacyFileLocation(checksum)
    if (!await fileExists(legacypath)) return false
    try {
      if (await fileExists(this.#getFileLocation(checksum))) await unlink(legacypath)
      else await this.#moveToPerm(legacypath, checksum)
      return true
    } catch (e: unknown) {
      if (isENOENT(e)) return false // a concurrent migration or remove got there first
      throw e
    }
  }

  /**
   * Moves every legacy base64url-named file to its hex location. Returns the number of files moved.
   */
  async migrateLegacyFiles () {
    let count = 0
    for await (const checksum of this.checksums()) {
      if (await this.migrateLegacyFile(checksum)) count += 1
    }
    return count
  }

  /**
   * Yields the base64url checksum of every file in permdir, including legacy base64url-named files.
   * Unless the filesystem is shown to be case-sensitive, legacy files are hashed to recover their true checksum,
   * and skipped if their contents don't match their name.
   */
  async* checksums () {
    const top = (await readdir(this.options.permdir, { withFileTypes: true })).filter(a => a.isDirectory() && /^[\w\-]$/v.test(a.name))
    const names = new Set(top.map(a => a.name))
    // seeing both x/ and X/ proves the filesystem is case-sensitive, so legacy names can be trusted without rehashing
    const caseSensitive = top.some(a => a.name !== a.name.toLowerCase() && names.has(a.name.toLowerCase()))
    for (const a of top) {
      for await (const b of await opendir(`${this.options.permdir}${a.name}`)) {
        if (!b.isDirectory() || !/^[\w\-]$/v.test(b.name)) continue
        // read the whole leaf up front so callers can rename files during iteration
        for (const f of await readdir(`${this.options.permdir}${a.name}/${b.name}`, { withFileTypes: true })) {
          if (!f.isFile()) continue
          // on case-insensitive filesystems, folder names may not match the case of the checksum
          const name = a.name + b.name + f.name
          if (/^[0-9a-f]{64}$/v.test(name.toLowerCase())) yield Buffer.from(name, 'hex').toString('base64url')
          else if (/^[\w\-]{43}$/v.test(name)) {
            if (caseSensitive) yield name
            else {
              const checksum = await this.#hashFile(`${this.options.permdir}${a.name}/${b.name}/${f.name}`)
              if (checksum.toLowerCase() === name.toLowerCase()) yield checksum // skip corrupted files
            }
          }
        }
      }
    }
  }

  async remove (checksum: string) {
    // legacy first, so a concurrent migration can't move it to the hex location after we've checked there
    for (const filepath of [this.#getLegacyFileLocation(checksum), this.#getFileLocation(checksum)]) {
      try {
        await unlink(filepath)
      } catch (e: unknown) {
        if (!isENOENT(e)) throw e
      }
    }
  }
}

export const fileHandler = new FileSystemHandler()
