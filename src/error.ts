import type { ValidationMessage } from '@txstate-mws/fastify-shared'
import type { FastifySchemaValidationError } from 'fastify/types/schema'
import { getReasonPhrase } from 'http-status-codes'

export class HttpError extends Error {
  public statusCode: number
  constructor (statusCode: number, message?: string) {
    if (!message) {
      if (statusCode === 401) message = 'Authentication is required.'
      else if (statusCode === 403) message = 'You are not authorized for that.'
      else message = getReasonPhrase(statusCode)
    }
    super(message)
    this.statusCode = statusCode
  }
}

export class FailedValidationError extends HttpError {
  constructor (public errors: Record<string, string[]>) {
    super(422, 'Validation failure.')
    this.errors = errors
  }
}

export class ValidationError extends HttpError {
  constructor (message: string, public path?: string, public type?: ValidationMessage['type']) {
    super(422, message)
  }
}

export class ValidationErrors extends HttpError {
  constructor (public errors: ValidationMessage[]) {
    super(422, errors[0]?.message)
  }
}

export function fstValidationToMessage (v: FastifySchemaValidationError) {
  const instancePath = v.keyword === 'required' ? v.instancePath + '/' + (v.params.missingProperty as string) : v.instancePath
  return { message: v.message, path: instancePath.substring(1).replace(/\//g, '.'), type: 'error' }
}
