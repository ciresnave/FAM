// Local Account Bootstrap
//
// Creates an account without an identity provider, so a fresh clone can be run
// without first registering a Google or GitHub OAuth application. Before this,
// the OAuth callback was the only code path that created an account, which made
// FAM inspectable but not runnable.
//
// Deliberately NOT exposed as an HTTP route. An endpoint that mints account
// credentials is an authentication bypass by construction, and gating one on an
// environment variable means a misconfiguration becomes a remote hole. This runs
// against the database directly, so reaching it already requires local
// filesystem access and the server secret — at which point the account boundary
// was never the thing protecting you.

import { randomUUID } from 'crypto';
import type { DatabaseContext } from '../db/transaction';
import { validateAccountId } from '../types/validation';
import { ConflictError } from '../types/errors';
import { hashToken } from './oauth';

const TOKEN_TTL_DAYS = 30;

export interface BootstrapResult {
  account_id: string;
  token: string;
  created: boolean;
}

/**
 * Create (or re-issue a token for) a local account.
 *
 * The account is left with no provider binding. It cannot be claimed by an
 * OAuth login: resolveAccountForProvider refuses any address that already
 * belongs to an account, bound or not.
 *
 * Re-running for an existing local account issues a NEW token and invalidates
 * the previous one — `authorizations` is UNIQUE(account_id, server_id), so
 * there is one live account token at a time.
 */
export async function bootstrapAccount(
  ctx: DatabaseContext,
  email: string,
  serverSecret: string
): Promise<BootstrapResult> {
  validateAccountId(email);

  if (!serverSecret) {
    throw new Error('FAM_SERVER_SECRET is required to issue an account token.');
  }

  const existing = ctx.accounts.getById(email);

  if (existing && (existing.provider || existing.provider_account_id)) {
    throw new ConflictError(
      `Account ${email} is owned by an identity provider. Sign in through that ` +
        `provider instead — bootstrapping over it would hand out a credential ` +
        `for somebody else's identity.`
    );
  }

  const account = existing ?? ctx.accounts.create(email, email);

  const token = randomUUID();
  const tokenHash = await hashToken(token, serverSecret);

  ctx.db.run(
    `INSERT OR REPLACE INTO authorizations (id, account_id, server_id, token_hash, expires_at)
     VALUES (?, ?, 'local', ?, datetime('now', ?))`,
    [randomUUID(), account.id, tokenHash, `+${TOKEN_TTL_DAYS} days`]
  );

  return { account_id: account.id, token, created: !existing };
}
