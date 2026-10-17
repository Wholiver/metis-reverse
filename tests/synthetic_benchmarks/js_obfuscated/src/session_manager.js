class SessionManager {
  constructor(cryptoUtil, defaultTtlSeconds = 3600) {
    this._crypto = cryptoUtil;
    this._defaultTtl = defaultTtlSeconds;
    this._sessions = new Map();
  }

  createSession(userId, role = "user", currentTs = null) {
    const timestamp = currentTs || Math.floor(Date.now() / 1000);
    const sessionPayload = {
      userId,
      role,
      issuedAt: timestamp,
      expiresAt: timestamp + this._defaultTtl
    };
    const signature = this._crypto.signToken(sessionPayload);
    const sessionId = `sess_${this._crypto.computeHash(userId + "_" + timestamp).slice(0, 16)}`;

    const record = {
      sessionId,
      payload: sessionPayload,
      signature,
      isActive: true
    };
    this._sessions.set(sessionId, record);
    return record;
  }

  validateSessionToken(sessionId, tokenSig, currentTs = null) {
    const session = this._sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    if (!session.isActive) {
      throw new Error("Session is revoked");
    }
    const now = currentTs || Math.floor(Date.now() / 1000);
    if (now > session.payload.expiresAt) {
      throw new Error("Session expired");
    }
    if (!this._crypto.verifySignature(session.payload, tokenSig)) {
      throw new Error("Invalid session signature");
    }
    return { valid: true, user: session.payload.userId, role: session.payload.role };
  }

  revokeSession(sessionId) {
    const session = this._sessions.get(sessionId);
    if (session) {
      session.isActive = false;
      return true;
    }
    return false;
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { SessionManager };
}
