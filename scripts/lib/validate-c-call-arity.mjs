#!/usr/bin/env node
import { readFile } from 'node:fs/promises'

const [sourcePath, ...rawContracts] = process.argv.slice(2)
if (sourcePath === undefined || rawContracts.length === 0) {
  console.error('usage: validate-c-call-arity <source> <symbol:arity> [...]')
  process.exit(2)
}

const contracts = rawContracts.map(value => {
  const match = /^(?<symbol>[A-Za-z_]\w*):(?<arity>\d+)$/u.exec(value)
  if (!match?.groups) throw new Error(`invalid C call contract: ${value}`)
  return { symbol: match.groups.symbol, arity: Number(match.groups.arity) }
})
const source = await readFile(sourcePath, 'utf8')
const sanitized = stripCommentsAndLiterals(source)

for (const contract of contracts) {
  const calls = callArities(sanitized, contract.symbol)
  if (calls.length === 0) throw new Error(`${contract.symbol} is absent from ${sourcePath}`)
  const invalid = calls.find(call => call.arity !== contract.arity)
  if (invalid) {
    throw new Error(
      `${contract.symbol} call at line ${invalid.line} has ${invalid.arity} arguments; expected ${contract.arity}`,
    )
  }
}

function callArities(value, symbol) {
  const matches = []
  const pattern = new RegExp(`\\b${symbol}\\s*\\(`, 'gu')
  for (const match of value.matchAll(pattern)) {
    const open = match.index + match[0].lastIndexOf('(')
    let depth = 1
    let commas = 0
    let close = open + 1
    for (; close < value.length && depth > 0; close += 1) {
      if (value[close] === '(' || value[close] === '[' || value[close] === '{') depth += 1
      else if (value[close] === ')' || value[close] === ']' || value[close] === '}') depth -= 1
      else if (value[close] === ',' && depth === 1) commas += 1
    }
    if (depth !== 0) throw new Error(`${symbol} call at line ${lineOf(value, open)} is unterminated`)
    const body = value.slice(open + 1, close - 1).trim()
    matches.push({ line: lineOf(value, open), arity: body === '' ? 0 : commas + 1 })
  }
  return matches
}

function stripCommentsAndLiterals(value) {
  return value.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/gu,
    match => match.replace(/[^\n]/gu, ' '),
  )
}

function lineOf(value, index) {
  return value.slice(0, index).split('\n').length
}
