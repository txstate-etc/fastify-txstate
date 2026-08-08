import { Readable } from 'node:stream'
import { ReadableStream, type ReadableStreamDefaultReader } from 'node:stream/web'

export interface FormDataTextField {
  name: string
  value: string
}

export interface FormDataFileField {
  name: string
  value: ReadableStream | Readable
  filename?: string
  filetype?: string
  filesize?: number
}

export type FormDataField = FormDataTextField | FormDataFileField

/**
 * These next two interfaces are structural stand-ins for the parts that
 * @fastify/multipart's request.parts() yields. I don't want to import types from
 * @fastify/multipart because that would force it on everyone who installs this
 * library, even people who never accept an upload.
 */
export interface MultipartFilePart {
  type: 'file'
  fieldname: string
  filename: string
  mimetype: string
  file: Readable
}

export interface MultipartValuePart {
  type: 'field'
  fieldname: string
  value: unknown
}

export type MultipartPart = MultipartFilePart | MultipartValuePart

/**
 * Send a POST request with a multipart/form-data body, streaming file contents
 * instead of buffering them. Returns the fetch Response.
 *
 * You can provide the fields two ways:
 *
 * An array works when you already know all the fields up front. If you also provide
 * `filesize` on every file field, I can compute a Content-Length for the request;
 * otherwise it goes out with chunked transfer encoding. The file contents are still
 * streamed either way -- only the list of fields has to be complete.
 *
 * An async iterable is for when you can't know the fields up front, most importantly
 * when you're proxying an incoming multipart request through to another server. The
 * parts iterator from @fastify/multipart refuses to yield the next part until you've
 * consumed the current part's file stream, so collecting the parts into an array
 * first will hang the request forever. Hand me an async iterable instead and I'll
 * pull each field from it only after I've finished sending the previous one, which
 * is exactly the consumption order the parts iterator needs. See
 * formDataFieldsFromParts for the easy way to construct that iterable.
 */
export async function postFormData (url: string, fields: FormDataField[] | AsyncIterable<FormDataField>, headers: Record<string, any> = {}) {
  const encoder = new TextEncoder()
  const boundary = `${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`
  const footer = `--${boundary}--\r\n`
  let totalSize: number | undefined
  let nextChunk: () => Promise<FormDataChunk | undefined>
  let cancelRemaining: () => void
  if (Array.isArray(fields)) {
    const chunks = fields.map(field => new FormDataChunk(boundary, encoder, field))
    totalSize = chunks.some(chunk => chunk.contentsize == null) ? undefined : chunks.reduce((sum, chunk) => sum + chunk.extrasize + chunk.contentsize!, Buffer.byteLength(footer))
    let i = 0
    nextChunk = async () => {
      const chunk = chunks[i]
      i += 1
      return chunk
    }
    cancelRemaining = () => {
      for (const chunk of chunks) void chunk.contentReader.cancel()
    }
  } else {
    const iterator = fields[Symbol.asyncIterator]()
    nextChunk = async () => {
      const result = await iterator.next()
      return result.done ? undefined : new FormDataChunk(boundary, encoder, result.value)
    }
    cancelRemaining = () => {
      void iterator.return?.()
    }
  }
  headers = {
    ...headers,
    'Content-Type': `multipart/form-data; boundary=${boundary}`
  }
  if (totalSize) {
    headers['Content-Length'] = totalSize.toString()
  }
  let chunk: FormDataChunk | undefined
  let part: 'header' | 'content' | 'footer' = 'header'
  const stream = new ReadableStream({
    // every pull MUST enqueue at least one chunk (or close the stream) before it
    // returns - the consumer's pending read is only guaranteed to trigger another
    // pull while this one is still running, so a pull that returns empty-handed
    // can strand the consumer waiting forever
    async pull (controller) {
      while (true) {
        if (part === 'header') {
          chunk = await nextChunk()
          if (chunk == null) {
            controller.enqueue(encoder.encode(footer))
            controller.close()
          } else {
            controller.enqueue(encoder.encode(chunk.header))
            part = 'content'
          }
          return
        } else if (part === 'content') {
          const result = await chunk!.contentReader.read()
          if (result.done) {
            part = 'footer'
            continue
          }
          controller.enqueue(result.value as Uint8Array)
          return
        } else {
          controller.enqueue(encoder.encode(chunk!.footer))
          part = 'header'
          return
        }
      }
    },
    cancel () {
      void chunk?.contentReader.cancel()
      cancelRemaining()
    }
  })
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- duplex and node ReadableStream aren't in standard RequestInit types
  return await fetch(url, {
    method: 'POST',
    headers,
    duplex: 'half',
    body: stream
  } as any)
}

/**
 * Convert the parts iterator from @fastify/multipart's request.parts() into the async
 * iterable of fields that postFormData accepts, so that proxying an upload through to
 * another server is one line:
 *
 * @example
 * const resp = await postFormData('http://other-service/upload', formDataFieldsFromParts(req.parts()))
 *
 * Each file flows through as it arrives without ever being buffered, so this is safe
 * for files of any size. Non-file fields come along too; a field that @fastify/multipart
 * parsed as JSON gets re-stringified on the way out.
 */
export async function* formDataFieldsFromParts (parts: AsyncIterable<MultipartPart>): AsyncIterable<FormDataField> {
  for await (const part of parts) {
    if (part.type === 'file') {
      yield { name: part.fieldname, value: part.file, filename: part.filename, filetype: part.mimetype }
    } else {
      yield { name: part.fieldname, value: typeof part.value === 'string' ? part.value : JSON.stringify(part.value) }
    }
  }
}

/**
 * Same as formDataFieldsFromParts, but forwards only the files and drops any
 * accompanying text fields. Useful when the text fields drove decisions on your
 * own server and the destination only needs the upload itself.
 *
 * Dropping a text field is safe because @fastify/multipart has already buffered
 * its value by the time it reaches us -- there's no stream left behind that could
 * stall the parts iterator.
 */
export async function* formDataFilesFromParts (parts: AsyncIterable<MultipartPart>): AsyncIterable<FormDataFileField> {
  for await (const field of formDataFieldsFromParts(parts)) {
    if (isFileField(field)) yield field
  }
}

function isFileField (field: FormDataField): field is FormDataFileField {
  return 'filename' in field || 'filetype' in field || 'filesize' in field || (typeof field.value === 'object' && 'getReader' in field.value)
}

class FormDataChunk {
  header: string
  footer: string
  extrasize: number
  contentsize: number | undefined
  contentReader: ReadableStreamDefaultReader
  constructor (boundary: string, encoder: TextEncoder, field: FormDataField) {
    this.header = `--${boundary}\r\nContent-Disposition: form-data; name="${field.name}"`
    this.footer = '\r\n'
    if (isFileField(field)) {
      this.header += `; filename="${field.filename ?? field.name}"\r\nContent-Type: ${field.filetype ?? 'application/octet-stream'}`
      this.contentsize = field.filesize
      this.contentReader = (field.value instanceof Readable ? ReadableStream.from(field.value) : field.value).getReader()
    } else {
      const encoded = encoder.encode(field.value)
      this.contentsize = encoded.length
      this.contentReader = new ReadableStream({
        start: controller => {
          controller.enqueue(encoded)
          controller.close()
        }
      }).getReader()
    }
    this.header += '\r\n\r\n'
    this.extrasize = Buffer.byteLength(this.header) + Buffer.byteLength(this.footer)
  }
}
