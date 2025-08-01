import * as url from 'url'
import { readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import * as prettier from 'prettier'

const __dirname = url.fileURLToPath(new URL('.', import.meta.url))

const labelsDef = JSON.parse(
  readFileSync(
    join(__dirname, '..', '..', 'definitions', 'labels.json'),
    'utf8',
  ),
)

writeFileSync(
  join(__dirname, '..', '..', 'src', 'moderation', 'const', 'labels.ts'),
  await gen(),
  'utf8',
)

async function gen() {
  const knownValues = new Set()
  const flattenedLabelDefs = []

  for (const { alias: aliases, ...label } of labelsDef) {
    knownValues.add(label.identifier)
    flattenedLabelDefs.push([label.identifier, { ...label, locales: [] }])

    if (aliases) {
      for (const alias of aliases) {
        knownValues.add(alias)
        flattenedLabelDefs.push([
          alias,
          {
            ...label,
            identifier: alias,
            locales: [],
            comment: `@deprecated alias for \`${label.identifier}\``,
          },
        ])
      }
    }
  }

  let labelDefsStr = `{`
  for (const [key, { comment, ...value }] of flattenedLabelDefs) {
    const commentStr = comment ? `\n/** ${comment} */\n` : ''
    labelDefsStr += `${commentStr}'${key}': ${JSON.stringify(value, null, 2)},`
  }
  labelDefsStr += `}`

  return prettier.format(
    `/** this doc is generated by ./scripts/code/labels.mjs **/
  import {InterpretedLabelValueDefinition, LabelPreference} from '../types'

  export type KnownLabelValue = ${Array.from(knownValues)
    .map((value) => `"${value}"`)
    .join(' | ')}

  export const DEFAULT_LABEL_SETTINGS: Record<string, LabelPreference> = ${JSON.stringify(
    Object.fromEntries(
      labelsDef
        .filter((label) => label.configurable)
        .map((label) => [label.identifier, label.defaultSetting]),
    ),
  )}

  export const LABELS: Record<KnownLabelValue, InterpretedLabelValueDefinition> = ${labelDefsStr}
  `,
    { semi: false, parser: 'typescript', singleQuote: true },
  )
}

export {}
