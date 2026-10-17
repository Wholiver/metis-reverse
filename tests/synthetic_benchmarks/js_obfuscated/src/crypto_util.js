const crypto = require("crypto");

class CryptoUtil {
  constructor(secretKey = "metis_default_hmac_secret_2026") {
    this._secretKey = secretKey;
    this._algorithm = "sha256";
  }

  computeHash(data) {
    if (!data) return "";
    return crypto.createHash(this._algorithm).update(String(data)).digest("hex");
  }

  signToken(payload) {
    const serialized = typeof payload === "string" ? payload : JSON.stringify(payload);
    return crypto.createHmac(this._algorithm, this._secretKey).update(serialized).digest("hex");
  }

  verifySignature(payload, expectedSig) {
    const actualSig = this.signToken(payload);
    if (!expectedSig || actualSig.length !== expectedSig.length) return false;
    return crypto.timingSafeEqual(Buffer.from(actualSig), Buffer.from(expectedSig));
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { CryptoUtil };
}
