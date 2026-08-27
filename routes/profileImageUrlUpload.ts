/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

async function isSsrfUrl (url: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(url)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return true
    }

    let hostname = parsedUrl.hostname
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1)
    }

    // Resolve IP address
    let ip: string
    try {
      const lookupResult = await dns.promises.lookup(hostname)
      ip = lookupResult.address
    } catch (dnsErr) {
      // If DNS resolution fails, block it to prevent potential SSRF
      return true
    }

    // Validate resolved IP address
    if (net.isIPv4(ip)) {
      const parts = ip.split('.').map(Number)
      const [oct1, oct2] = parts

      // Loopback: 127.0.0.0/8
      if (oct1 === 127) return true

      // Private IPv4 (RFC 1918):
      // 10.0.0.0/8
      if (oct1 === 10) return true
      // 172.16.0.0/12
      if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true
      // 192.168.0.0/16
      if (oct1 === 192 && oct2 === 168) return true

      // Link-local: 169.254.0.0/16
      if (oct1 === 169 && oct2 === 254) return true

      // Shared address space / Carrier Grade NAT: 100.64.0.0/10
      if (oct1 === 100 && oct2 >= 64 && oct2 <= 127) return true

      // Local/Broadcast: 0.0.0.0/8
      if (oct1 === 0) return true

      // Multicast / Reserved: 224.0.0.0/4 and 240.0.0.0/4
      if (oct1 >= 224) return true

      return false
    } else if (net.isIPv6(ip)) {
      const normalizedIp = ip.toLowerCase()

      // Loopback: ::1
      if (normalizedIp === '::1' || normalizedIp === '0:0:0:0:0:0:0:1') return true

      // Unspecified: ::
      if (normalizedIp === '::' || normalizedIp === '0:0:0:0:0:0:0:0') return true

      // Link-local: fe80::/10
      if (normalizedIp.startsWith('fe8') || normalizedIp.startsWith('fe9') || normalizedIp.startsWith('fea') || normalizedIp.startsWith('feb')) return true

      // Unique local: fc00::/7 (fc00:: to fdff::)
      if (normalizedIp.startsWith('fc') || normalizedIp.startsWith('fd')) return true

      return false
    }

    return true
  } catch (err) {
    // Invalid URL structure
    return true
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (await isSsrfUrl(url)) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
