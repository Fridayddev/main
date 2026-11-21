/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { assertValidVideoHash } from './videoHash'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
}

export type VerificationResultTabId = 'summary' | 'chain' | 'corroboration'

export interface StatementIdentityResolutionInput {
  verifyHash?: string | null
  videoHashInput?: string | null
  proofIdInput?: string | null
  events?: ProofEvent[] | null
  chainProof?: ChainProofRecord | null
}

export interface ResolvedVerifiedStatementIdentity {
  statementDigest: string
  statementKey: string
  proofId: string | null
  metadataHash: string | null
  chainSource: string | null
  matchingEvents: ProofEvent[]
}

function normalizeDigest(value?: string | null): string {
  if (!value) return ''
  const trimmed = value.trim()
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    return trimmed.slice(2).toLowerCase()
  }
  return trimmed.toLowerCase()
}

function normalizeProofId(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed) return null
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    return `0x${trimmed.slice(2).toLowerCase()}`
  }
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return `0x${trimmed.toLowerCase()}`
  }
  return trimmed
}

export function shouldResetDependentTabState(
  previousStatementKey: string,
  nextStatementKey: string,
): boolean {
  return previousStatementKey !== nextStatementKey
}

export function resolveVerifiedStatementIdentity(
  input: StatementIdentityResolutionInput,
): ResolvedVerifiedStatementIdentity {
  const statementDigest = normalizeDigest(input.verifyHash)
  const statementKey = statementDigest || '__empty_statement__'

  if (!statementDigest) {
    return {
      statementDigest: '',
      statementKey: '__empty_statement__',
      proofId: null,
      metadataHash: null,
      chainSource: null,
      matchingEvents: [],
    }
  }

  const matchingEvents = (input.events || []).filter(
    (event) => normalizeDigest(event.video_hash) === statementDigest,
  )

  let resolvedProofId: string | null = null

  for (const event of matchingEvents) {
    if (event.proof_id && event.proof_id.trim()) {
      resolvedProofId = normalizeProofId(event.proof_id)
      break
    }
  }

  const chainProof = input.chainProof
  const chainMatches = !!(chainProof && normalizeDigest(chainProof.videoHash) === statementDigest)

  if (!resolvedProofId && chainMatches && chainProof?.proofId) {
    resolvedProofId = normalizeProofId(chainProof.proofId)
  }

  if (!resolvedProofId && input.proofIdInput) {
    const videoInput = normalizeDigest(input.videoHashInput)
    if (!videoInput || videoInput === statementDigest) {
      resolvedProofId = normalizeProofId(input.proofIdInput)
    }
  }

  const metadataHash = chainMatches && chainProof?.metadataHash ? chainProof.metadataHash : null
  const chainSource = chainMatches && chainProof?.source ? chainProof.source : null

  return {
    statementDigest,
    statementKey,
    proofId: resolvedProofId,
    metadataHash,
    chainSource,
    matchingEvents,
  }
}

/**
 * Run the verification flow for an already-computed video hash.
 *
 * The hash is validated before any network call is made so a malformed value
 * (from a share link or manifest) cannot inject path segments or query strings.
 */
export async function runVerificationFlow(
  videoHash: string,
  options: { signal?: AbortSignal; sourceAddress?: string } = {},
): Promise<VerificationResult> {
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata: events.length > 0,
    events,
    onChain: onChain,
  }
}

/**
 * Convenience helper: extract metadata from an uploaded file and then run the
 * verification flow for the supplied video hash.
 */
export async function verifyUploadedVideo(
  file: File,
  videoHash: string,
  options: { signal?: AbortSignal; sourceAddress?: string } = {},
): Promise<VerificationResult> {
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  const result = await runVerificationFlow(safeHash, options)
  return { ...result, hasHarpocratesMetadata: extract.hasHarpocratesMetadata }
}
