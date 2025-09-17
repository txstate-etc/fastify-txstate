import { Readable } from 'node:stream'
import { ReadableStream, ReadableStreamDefaultReader } from 'node:stream/web'

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

export async function postFormData (url: string, fields: FormDataField[], headers: Record<string, any> = {}) {
  const encoder = new TextEncoder()
  const boundary = `${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`
  const footer = `--${boundary}--\r\n`
  const chunks = fields.map(field => new FormDataChunk(boundary, encoder, field))
  const totalSize = chunks.some(chunk => chunk.contentsize == null) ? undefined : chunks.reduce((sum, chunk) => sum + chunk.extrasize + chunk.contentsize!, 0)
  headers = {
    ...headers,
    'Content-Type': `multipart/form-data; boundary=${boundary}`
  }
  if (totalSize) {
    headers['Content-Length'] = totalSize.toString()
  }
  let i = 0
  let part: 'header' | 'content' | 'footer' = 'header'
  const stream = new ReadableStream({
    async pull (controller) {
      if (i === chunks.length) {
        controller.enqueue(encoder.encode(footer))
        controller.close()
      } else {
        const chunk = chunks[i]
        if (part === 'header') {
          controller.enqueue(encoder.encode(chunk.header))
          part = 'content'
        } else if (part === 'content') {
          const { value, done } = await chunk.contentReader.read()
          if (done) part = 'footer'
          else controller.enqueue(value)
        } else if (part === 'footer') {
          controller.enqueue(encoder.encode(chunk.footer))
          i++
          part = 'header'
        }
      }
    },
    cancel () {
      for (const chunk of chunks) {
        if (chunk.contentReader.cancel) {
          chunk.contentReader.cancel()
        }
      }
    }
  })
  return await fetch(url, {
    method: 'POST',
    headers,
    duplex: 'half',
    body: stream
  } as any)
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
