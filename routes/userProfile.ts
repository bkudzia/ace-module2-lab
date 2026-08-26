/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function safeEval (code: string): any {
  const tokens: Array<{ type: string, value: any }> = []
  let i = 0

  while (i < code.length) {
    const char = code[i]

    if (/\s/.test(char)) {
      i++
      continue
    }

    if (/[0-9]/.test(char) || (char === '.' && /[0-9]/.test(code[i + 1] || ''))) {
      let numStr = ''
      while (i < code.length && /[0-9.]/.test(code[i])) {
        numStr += code[i]
        i++
      }
      const val = parseFloat(numStr)
      if (isNaN(val)) throw new Error('Invalid number')
      tokens.push({ type: 'NUMBER', value: val })
      continue
    }

    if (char === "'" || char === '"' || char === '`') {
      const quote = char
      let strVal = ''
      i++
      let escaped = false
      while (i < code.length) {
        if (escaped) {
          strVal += code[i]
          escaped = false
        } else if (code[i] === '\\') {
          escaped = true
        } else if (code[i] === quote) {
          break
        } else {
          strVal += code[i]
        }
        i++
      }
      if (i >= code.length) throw new Error('Unterminated string literal')
      i++
      tokens.push({ type: 'STRING', value: strVal })
      continue
    }

    if (['+', '-', '*', '/', '(', ')'].includes(char)) {
      tokens.push({ type: 'OPERATOR', value: char })
      i++
      continue
    }

    if (code.startsWith('true', i)) {
      tokens.push({ type: 'BOOLEAN', value: true })
      i += 4
      continue
    }
    if (code.startsWith('false', i)) {
      tokens.push({ type: 'BOOLEAN', value: false })
      i += 5
      continue
    }
    if (code.startsWith('null', i)) {
      tokens.push({ type: 'NULL', value: null })
      i += 4
      continue
    }

    throw new Error(`Forbidden character or symbol: ${char}`)
  }

  let tokenIdx = 0

  function peek () {
    return tokens[tokenIdx]
  }

  function consume (expectedType?: string, expectedValue?: any) {
    const token = tokens[tokenIdx]
    if (!token) throw new Error('Unexpected end of input')
    if (expectedType && token.type !== expectedType) {
      throw new Error(`Expected token type ${expectedType}, got ${token.type}`)
    }
    if (expectedValue !== undefined && token.value !== expectedValue) {
      throw new Error(`Expected token value ${expectedValue}, got ${token.value}`)
    }
    tokenIdx++
    return token
  }

  function parseFactor (): any {
    const token = peek()
    if (!token) throw new Error('Unexpected end of expression')

    if (token.type === 'NUMBER' || token.type === 'STRING' || token.type === 'BOOLEAN' || token.type === 'NULL') {
      consume()
      return token.value
    }

    if (token.type === 'OPERATOR' && token.value === '(') {
      consume('OPERATOR', '(')
      const val = parseExpr()
      consume('OPERATOR', ')')
      return val
    }

    throw new Error(`Unexpected token: ${token.value}`)
  }

  function parseTerm (): any {
    let val = parseFactor()
    while (true) {
      const next = peek()
      if (next && next.type === 'OPERATOR' && (next.value === '*' || next.value === '/')) {
        const op = consume().value
        const right = parseFactor()
        if (op === '*') val = val * right
        else val = val / right
      } else {
        break
      }
    }
    return val
  }

  function parseExpr (): any {
    let val = parseTerm()
    while (true) {
      const next = peek()
      if (next && next.type === 'OPERATOR' && (next.value === '+' || next.value === '-')) {
        const op = consume().value
        const right = parseTerm()
        if (op === '+') val = val + right
        else val = val - right
      } else {
        break
      }
    }
    return val
  }

  if (tokens.length === 0) {
    return ''
  }

  const result = parseExpr()
  if (tokenIdx < tokens.length) {
    throw new Error('Unexpected tokens at the end of expression')
  }
  return result
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = safeEval(code)
      } catch (err) {
        username = '\\\\' + username
      }
    } else {
      username = '\\\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
