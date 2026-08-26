/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'node:path'
import fs from 'node:fs'
import config from 'config'
import { themes } from '../views/themes/themes'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const entities = new Entities()

const router = express.Router()

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const email = loggedInUser.data.email

    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (answer == null) {
        throw new Error('No answer found!')
      }
      const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      if (question == null) {
        throw new Error('No question found!')
      }

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      res.render('dataErasureForm', {
        userEmail: email,
        securityQuestion: question.question,
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      })
    } catch (error) {
      next(error)
    }
  })()
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

router.post('/', (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): void => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      await PrivacyRequestModel.create({
        UserId: loggedInUser.data.id,
        deletionRequested: true
      })

      res.clearCookie('token')

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      const themeVars = {
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      }

      if (req.body.layout) {
        const viewsDir = path.resolve(__dirname, '../views')
        const packageJsonPath = path.resolve(__dirname, '../package.json')

        let resolvedPath = path.resolve(req.body.layout)
        if (!path.isAbsolute(req.body.layout)) {
          resolvedPath = path.resolve(viewsDir, req.body.layout)
        }

        const projectDir = path.resolve(__dirname, '..')
        const isInsideProject = resolvedPath.startsWith(projectDir + path.sep) || resolvedPath === projectDir

        let isAllowed = false
        if (isInsideProject) {
          if (fs.existsSync(resolvedPath)) {
            const isPackageJson = resolvedPath === packageJsonPath
            const isInsideViews = resolvedPath.startsWith(viewsDir + path.sep)
            if (isPackageJson || isInsideViews) {
              const isForbiddenFile: boolean = (resolvedPath.toLowerCase().includes('ftp') || resolvedPath.toLowerCase().includes('ctf.key') || resolvedPath.toLowerCase().includes('encryptionkeys'))
              if (!isForbiddenFile) {
                isAllowed = true
              }
            }
          } else {
            // For non-existing files inside the project, let them pass to res.render so it throws ENOENT naturally as expected by the test
            isAllowed = true
          }
        }

        if (isAllowed) {
          res.render('dataErasureResult', {
            ...req.body,
            ...themeVars
          }, (error: any, html: any) => {
            if (!html || error) {
              next(new Error(error.message))
            } else {
              const sendlfrResponse: string = html.slice(0, 100) + '......'
              res.send(sendlfrResponse)
              challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
            }
          })
        } else {
          next(new Error('File access not allowed'))
        }
      } else {
        res.render('dataErasureResult', {
          ...req.body,
          ...themeVars
        })
      }
    } catch (error) {
      next(error)
    }
  })()
})

export default router
