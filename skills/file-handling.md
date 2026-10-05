# fastify-txstate: File Handling

Use this skill when the API needs to accept file uploads, proxy files to remote services, or store files.

## Streaming File Proxy with postFormData

`postFormData` constructs a multipart/form-data request from streams, letting you forward an incoming upload to a remote API without buffering the file in memory or on disk.

```javascript
import Server, { postFormData } from 'fastify-txstate'
const server = new Server()
server.app.post('/upload', async (req, res) => {
  const results = []
  for await (const part of req.parts()) {
    if (part.type === 'file') {
      const resp = await postFormData(
        'https://upstream.example.com/upload',
        [
          { name: 'key', value: `uploads/${part.filename}` },
          { name: 'file', value: part.file, filename: part.filename, filetype: part.mimetype }
        ],
        { Authorization: 'Bearer ...' }
      )
      results.push({ filename: part.filename, status: resp.status })
    }
  }
  return results
})
```

### Field types
- **Text field**: `{ name: string, value: string }`
- **File field**: `{ name: string, value: ReadableStream | Readable, filename?: string, filetype?: string, filesize?: number }`

If all file fields include `filesize`, a `Content-Length` header is set automatically. Otherwise the request is chunked.

The third argument is an optional headers object.

## File Storage with FileSystemHandler

`FileSystemHandler` streams uploaded files to the local filesystem, named by their hex-encoded SHA-256 checksum. `put` returns the shorter base64url form for storing in your database; every method accepts either form. Identical files are automatically deduplicated. Files are stored in a two-level directory structure based on the checksum (`ab/cd/ef01...`) to avoid overwhelming a single directory.

```javascript
import Server, { FileSystemHandler } from 'fastify-txstate'
const storage = new FileSystemHandler({ tmpdir: '/files/tmp', permdir: '/files/storage' })
await storage.init()

const server = new Server()
server.app.post('/upload', async (req, res) => {
  for await (const part of req.parts()) {
    if (part.type === 'file') {
      const { checksum, size } = await storage.put(part.file)
      // save the checksum in your database alongside whatever record it was uploaded against
    }
  }
})

server.app.get('/download/:checksum', async (req, res) => {
  const stream = storage.get(req.params.checksum)
  return res.send(stream)
})
```

### Methods
| Method | Description |
|--------|-------------|
| `init()` | Creates `tmpdir` and `permdir` if they don't exist and deletes tmp files left by a crash. Call before using the handler. |
| `put(stream)` | Streams a `Readable` to storage. Returns `{ checksum, size }`. |
| `get(checksum, range?)` | Returns a `Readable` stream for the file. Pass `{ start, end }` to read only part of it, e.g. an HTTP range request. Offsets are zero-based and inclusive. Clamp the range to the file's size before calling. |
| `remove(checksum)` | Deletes the file, and any folders that leaves empty. No-op if already gone. |
| `exists(checksum)` | Returns `true` if the file exists. |
| `fileSize(checksum)` | Returns the file size in bytes. |
| `migrateLegacyFiles()` | Runs `migrateLegacyFile` on every legacy file in storage. Returns the number of files moved. |
| `checksums()` | Async iterator over the base64url checksum of every stored file, including legacy files that haven't been migrated. On a case-insensitive filesystem (e.g. Azure Files over SMB) the case of folder names can be lost, so legacy files are hashed to recover their checksum and skipped if their contents don't match their name. Hashing is skipped once the presence of both an `x/` and an `X/` folder proves the filesystem is case-sensitive. |
| `migrateLegacyFile(checksum)` | Moves a file stored by an older version under its base64url name to its hex location. Returns `false` if there was no legacy file. |

Defaults: `tmpdir` = `/files/tmp/`, `permdir` = `/files/storage/`. A default instance is exported as `fileHandler`.

### Write integrity
`put` streams to a temp file while computing the SHA-256 hash, then re-reads the file to verify the hash matches before moving it to the permanent location. If verification fails, the temp file is cleaned up and an error is thrown.

## Swappable Storage with the FileHandler Interface

The `FileHandler` interface is exported so you can write alternative storage backends (e.g. S3, GCS). Design your API to accept a `FileHandler` as configuration — route handlers stay the same regardless of backend.

```javascript
import { FileSystemHandler, type FileHandler } from 'fastify-txstate'
import { S3FileHandler } from './s3filehandler.js'

const storage: FileHandler = process.env.FILE_STORAGE === 's3'
  ? new S3FileHandler({ bucket: process.env.S3_BUCKET })
  : new FileSystemHandler()
```

`postFormData` is useful for building cloud storage implementations, since it can stream files to a remote API without buffering.
