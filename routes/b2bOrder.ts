/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isSafeOrderLinesData (data: string): boolean {
  let str = String(data)

  // Normalize Unicode to NFKC form to prevent any unicode normalization bypasses
  str = str.normalize('NFKC')

  // 1. Unescape hex escapes: \xHH
  str = str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

  // 2. Unescape unicode escapes: \uHHHH
  str = str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

  // 3. Unescape unicode code point escapes: \u{HHHH}
  str = str.replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

  // 4. Unescape octal escapes: \OOO (up to 3 octal digits)
  str = str.replace(/\\([0-7]{1,3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)))

  // Strict structural and character-level controls to prevent sandbox escapes:
  // - Block brackets [ and ] to prevent bracket-based dynamic property access
  if (str.includes('[') || str.includes(']')) {
    return false
  }

  // - Block quotes ', " and ` to prevent string literal declaration/manipulation
  if (str.includes("'") || str.includes('"') || str.includes('`')) {
    return false
  }

  // - Block backslash \ to prevent escape sequences in the final code
  if (str.includes('\\')) {
    return false
  }

  // - Block dot . notation unless it is strictly part of a decimal number (e.g. 2.5)
  // All other occurrences of dots (property access, method invocation) are rejected.
  if (/(?<!\d)\.|\.(?!\d)/.test(str)) {
    return false
  }

  // - Block comment delimiters to prevent comment-based filter bypasses
  if (str.includes('//') || str.includes('/*') || str.includes('*/')) {
    return false
  }

  const lowerStr = str.toLowerCase()

  // Create a normalized version with all non-alphanumeric characters removed
  const normalized = lowerStr.replace(/[^a-z0-9]/g, '')

  const blocklist = [
    'this',
    'constructor',
    'prototype',
    'proto',
    'process',
    'require',
    'exec',
    'spawn',
    'childprocess',
    'function',
    'eval',
    'global',
    'window',
    'document',
    'fromcharcode',
    'callee',
    'caller',
    'arguments',
    'reflect',
    'proxy',
    'mainmodule',
    'import'
  ]

  for (const keyword of blocklist) {
    if (lowerStr.includes(keyword) || normalized.includes(keyword)) {
      return false
    }
  }

  return true
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        if (!isSafeOrderLinesData(orderLinesData)) {
          throw new Error('Blocked dangerous input')
        }
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
